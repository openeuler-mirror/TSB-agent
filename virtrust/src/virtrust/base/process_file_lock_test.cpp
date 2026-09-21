#include "virtrust/base/process_file_lock.h"

#include <gtest/gtest.h>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>
#include <signal.h>
#include <poll.h>

namespace virtrust {
namespace {
// 失败断言提前返回时仍关闭管道，避免测试自身泄漏描述符。
struct TestPipe {
    int fd[2] {-1, -1};
    TestPipe() { if (pipe(fd) != 0) { fd[0] = fd[1] = -1; } }
    ~TestPipe() { for (int value : fd) { if (value >= 0) { close(value); } } }
    TestPipe(const TestPipe &) = delete;
    TestPipe &operator=(const TestPipe &) = delete;
};

// 仅管理本用例创建的子进程：提前失败时终止并回收，正常完成后不重复操作 PID。
class TestChild {
public:
    explicit TestChild(pid_t pid) : pid_(pid) {}
    ~TestChild()
    {
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            int status;
            while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        }
    }
    TestChild(const TestChild &) = delete;
    TestChild &operator=(const TestChild &) = delete;
    bool Succeeded()
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            const auto result = waitpid(pid_, &status, WNOHANG);
            if (result == pid_) {
                pid_ = -1;
                return WIFEXITED(status) && WEXITSTATUS(status) == 0;
            }
            if (result < 0 && errno != EINTR) { return false; }
            std::this_thread::yield();
        }
        return false;
    }
private:
    pid_t pid_;
};

// 有限等待实际管道事件；超时是失败，不用固定 sleep 推断业务执行到了哪里。
bool Receive(int fd, char expected)
{
    pollfd event {fd, POLLIN, 0};
    int result;
    do { result = poll(&event, 1, 3000); } while (result < 0 && errno == EINTR);
    char value = 0;
    return result > 0 && read(fd, &value, 1) == 1 && value == expected;
}

// Linux /proc/locks 的箭头行代表真实内核等待者，而不是“即将调用 flock”的通知。
bool WaitForBlockedFlock(pid_t child)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        std::ifstream locks("/proc/locks");
        std::string line;
        while (std::getline(locks, line)) {
            std::istringstream fields(line);
            std::string id, arrow, kind, advisory, mode;
            pid_t owner = -1;
            if (fields >> id >> arrow >> kind >> advisory >> mode >> owner) {
                if (arrow == "->" && kind == "FLOCK" && owner == child) { return true; }
            }
        }
        std::this_thread::yield();
    }
    return false;
}
} // 匿名命名空间
// 每个用例使用独立临时目录，避免触碰业务锁或与其他测试相互干扰。
class ProcessFileLockTest : public testing::Test {
protected:
    // 创建唯一目录，锁文件由被测组件创建。
    void SetUp() override
    {
        char pattern[] = "/tmp/virtrust-lock-ut.XXXXXX";
        const auto *dir = mkdtemp(pattern);
        ASSERT_NE(dir, nullptr);
        directory = dir;
        path = directory + "/lock";
    }
    // 用例中的锁对象已析构、子进程已回收后，只清理本用例的临时目录。
    void TearDown() override
    {
        if (!directory.empty()) {
            std::filesystem::remove_all(directory);
        }
    }
    // mkdtemp 返回的本用例独占目录。
    std::string directory;
    // 父子进程共同竞争的锁文件路径。
    std::string path;
};

// 独占锁拒绝其他持有者，重复释放安全，释放后可重新取得共享锁。
TEST_F(ProcessFileLockTest, ExclusiveRejectsAnotherHolderUntilReleased)
{
    ProcessFileLock first, second;
    ASSERT_EQ(first.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    EXPECT_TRUE(first.OwnsLock());
    EXPECT_EQ(second.Acquire(path, LockMode::Shared, LockWait::Try), LockOutcome::Busy);
    EXPECT_FALSE(second.OwnsLock());
    EXPECT_TRUE(second.LastErrno() == EWOULDBLOCK || second.LastErrno() == EAGAIN);
    first.Release();
    first.Release();
    EXPECT_EQ(second.Acquire(path, LockMode::Shared, LockWait::Try), LockOutcome::Acquired);
    EXPECT_EQ(second.LastErrno(), 0);
}

// 多个共享锁可共存，但仍阻止独占锁进入。
TEST_F(ProcessFileLockTest, SharedHoldersExcludeExclusive)
{
    ProcessFileLock first, second, exclusive;
    ASSERT_EQ(first.Acquire(path, LockMode::Shared, LockWait::Try), LockOutcome::Acquired);
    ASSERT_EQ(second.Acquire(path, LockMode::Shared, LockWait::Try), LockOutcome::Acquired);
    EXPECT_EQ(exclusive.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Busy);
}

// 移动不丢失原锁；移动赋值释放接收方旧锁，最终析构释放接管的锁。
TEST_F(ProcessFileLockTest, MoveTransfersOwnershipAndDestructorReleases)
{
    ProcessFileLock contender;
    {
        ProcessFileLock first;
        ASSERT_EQ(first.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
        ProcessFileLock second(std::move(first));
        EXPECT_FALSE(first.OwnsLock());
        ProcessFileLock third;
        ASSERT_EQ(third.Acquire(directory + "/other", LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
        third = std::move(second);
        EXPECT_FALSE(second.OwnsLock());
        EXPECT_TRUE(third.OwnsLock());
        ProcessFileLock other;
        EXPECT_EQ(other.Acquire(directory + "/other", LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
        EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Busy);
    }
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    EXPECT_TRUE(std::filesystem::exists(path));
}

// 路径不存在属于系统错误，不能伪装成锁竞争。
TEST_F(ProcessFileLockTest, ReportsPathFailureRatherThanBusy)
{
    ProcessFileLock lock;
    EXPECT_EQ(lock.Acquire(directory + "/missing/lock", LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), ENOENT);
    EXPECT_FALSE(lock.OwnsLock());
}

// 验证拒绝符号链接和 FIFO；不据此声称 O_RDWR 打开 FIFO 必然阻塞。
TEST_F(ProcessFileLockTest, RejectsSymlinkAndFifo)
{
    ASSERT_EQ(symlink("target", path.c_str()), 0);
    ProcessFileLock lock;
    EXPECT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), ELOOP);
    ASSERT_EQ(mkfifo((directory + "/fifo").c_str(), 0600), 0);
    EXPECT_EQ(lock.Acquire(directory + "/fifo", LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), EINVAL);
    EXPECT_FALSE(lock.OwnsLock());
}

// 已持锁对象重复获取时明确报错，且不能因此释放原锁。
TEST_F(ProcessFileLockTest, ReacquireDoesNotLoseExistingLock)
{
    ProcessFileLock lock, contender;
    ASSERT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    EXPECT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), EALREADY);
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Busy);
}

// 子进程关闭继承副本后，父进程的独占锁仍必须有效。
TEST_F(ProcessFileLockTest, ChildReleaseCannotUnlockParent)
{
    ProcessFileLock parent;
    ASSERT_EQ(parent.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    const auto child = fork();
    ASSERT_GE(child, 0);
    TestChild childGuard(child);
    if (child == 0) {
        // 仅关闭继承的描述符；若调用 LOCK_UN，会同时解除父进程的锁。
        parent.Release();
        ProcessFileLock contender;
        _exit(contender.Acquire(path, LockMode::Exclusive, LockWait::Try) == LockOutcome::Busy ? 0 : 1);
    }
    ASSERT_TRUE(childGuard.Succeeded());
    parent.Release();
    ProcessFileLock contender;
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
}

// 不自动修复不安全文件：拒绝组/其他用户可访问的权限及硬链接别名。
TEST_F(ProcessFileLockTest, RejectsUnsafePermissionsAndHardlinks)
{
    {
        ProcessFileLock creator;
        ASSERT_EQ(creator.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    }
    ASSERT_EQ(chmod(path.c_str(), 0666), 0);
    ProcessFileLock lock;
    EXPECT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), EACCES);
    ASSERT_EQ(chmod(path.c_str(), 0600), 0);
    ASSERT_EQ(link(path.c_str(), (directory + "/alias").c_str()), 0);
    EXPECT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Error);
    EXPECT_EQ(lock.LastErrno(), EINVAL);
}

// 根据设备号和 inode 找到锁描述符，检查 CLOEXEC 标志；不等同于实际 exec 集成测试。
TEST_F(ProcessFileLockTest, DescriptorIsCloseOnExec)
{
    ProcessFileLock lock;
    ASSERT_EQ(lock.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    struct stat expected {};
    ASSERT_EQ(stat(path.c_str(), &expected), 0);
    // 确认只持有一个对应描述符，避免未找到描述符时误判测试通过。
    int matches = 0;
    for (const auto &entry : std::filesystem::directory_iterator("/proc/self/fd")) {
        int fd = std::stoi(entry.path().filename().string());
        struct stat actual {};
        if (fstat(fd, &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino) {
            ++matches;
            const int flags = fcntl(fd, F_GETFD);
            ASSERT_NE(flags, -1);
            EXPECT_NE(flags & FD_CLOEXEC, 0);
        }
    }
    EXPECT_EQ(matches, 1);
}

// 先确认内核中出现真实 flock 等待者，再释放父锁并验证子进程被唤醒。
TEST_F(ProcessFileLockTest, IndependentProcessCanBlockThenAcquireAfterRelease)
{
    ProcessFileLock parent;
    ASSERT_EQ(parent.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    // 子进程向父进程报告首次非阻塞竞争结果，避免用固定睡眠推测执行顺序。
    TestPipe ready;
    ASSERT_GE(ready.fd[0], 0);
    const auto child = fork();
    ASSERT_GE(child, 0);
    TestChild childGuard(child);
    if (child == 0) {
        parent.Release();
        ProcessFileLock contender;
        char result = contender.Acquire(path, LockMode::Exclusive, LockWait::Try) == LockOutcome::Busy ? 'B' : 'E';
        if (write(ready.fd[1], &result, 1) != 1) {
            _exit(2);
        }
        _exit(contender.Acquire(path, LockMode::Exclusive, LockWait::Block) == LockOutcome::Acquired ? 0 : 3);
    }
    ASSERT_TRUE(Receive(ready.fd[0], 'B'));
    ASSERT_TRUE(WaitForBlockedFlock(child));
    parent.Release();
    EXPECT_TRUE(childGuard.Succeeded());
}

// 父进程关闭自己的描述符不解除子进程仍持有的锁；子进程关闭后才能重新获得。
TEST_F(ProcessFileLockTest, InheritedDescriptorKeepsLockUntilChildCloses)
{
    ProcessFileLock parent;
    ASSERT_EQ(parent.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    TestPipe command, ready;
    ASSERT_GE(command.fd[0], 0);
    ASSERT_GE(ready.fd[0], 0);
    const auto child = fork();
    ASSERT_GE(child, 0);
    TestChild childGuard(child);
    if (child == 0) {
        char value;
        if (read(command.fd[0], &value, 1) != 1) { _exit(2); }
        parent.Release();
        if (write(ready.fd[1], "R", 1) != 1) { _exit(3); }
        // 保持子进程存活，证明释放由 close 而不是退出触发。
        _exit(read(command.fd[0], &value, 1) == 1 ? 0 : 4);
    }
    parent.Release();
    ProcessFileLock contender;
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Busy);
    ASSERT_EQ(write(command.fd[1], "C", 1), 1);
    ASSERT_TRUE(Receive(ready.fd[0], 'R'));
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    ASSERT_EQ(write(command.fd[1], "Q", 1), 1);
    EXPECT_TRUE(childGuard.Succeeded());
}

// 执行当前测试程序的独立探针入口，确认 exec 后没有锁文件描述符遗留。
TEST_F(ProcessFileLockTest, ExecClosesInheritedLockWhileChildRemainsAlive)
{
    ProcessFileLock parent;
    ASSERT_EQ(parent.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    TestPipe command, ready;
    ASSERT_GE(command.fd[0], 0);
    ASSERT_GE(ready.fd[0], 0);
    const std::string input = std::to_string(command.fd[0]);
    const std::string output = std::to_string(ready.fd[1]);
    const auto child = fork();
    ASSERT_GE(child, 0);
    TestChild childGuard(child);
    if (child == 0) {
        execl("/proc/self/exe", "process_file_lock_test", "--lock-exec-probe",
              path.c_str(), input.c_str(), output.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }
    ASSERT_TRUE(Receive(ready.fd[0], 'R'));
    ProcessFileLock contender;
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Busy);
    parent.Release();
    EXPECT_EQ(contender.Acquire(path, LockMode::Exclusive, LockWait::Try), LockOutcome::Acquired);
    ASSERT_EQ(write(command.fd[1], "Q", 1), 1);
    EXPECT_TRUE(childGuard.Succeeded());
}
} // 命名空间 virtrust

// exec 探针不初始化 GoogleTest；确认目标 inode 无描述符引用后通知父进程并等待退出指令。
int main(int argc, char **argv)
{
    if (argc == 5 && std::string(argv[1]) == "--lock-exec-probe") {
        struct stat expected {};
        if (stat(argv[2], &expected) != 0) { return 2; }
        for (const auto &entry : std::filesystem::directory_iterator("/proc/self/fd")) {
            struct stat actual {};
            int fd = std::stoi(entry.path().filename().string());
            if (fstat(fd, &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino) {
                return 3;
            }
        }
        if (write(std::stoi(argv[4]), "R", 1) != 1) { return 4; }
        char command;
        return read(std::stoi(argv[3]), &command, 1) == 1 ? 0 : 5;
    }
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
