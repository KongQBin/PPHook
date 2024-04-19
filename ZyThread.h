#ifndef ZYTHREAD_H
#define ZYTHREAD_H
#include <future>
//typedef future<typename result_of<T()>::type> Zyasync;
namespace ZyThread
{
    //编译参数 -std=c++11 -lpthread -Wl,--no-as-needed
    //autoRun 不关心线程是否结束
    template<typename T> inline void autoRun(T func)
    {
        std::thread t(func);
        t.detach();
        return;
    }

    //async 支持等待、超时等待、返回值获取等操作
    template<typename _Fn>
    inline std::future<typename std::result_of<_Fn()>::type>
    run(_Fn&& func)
    {
        return std::async(std::launch::async,func);
    }
    //判断线程是否结束
    template<typename T>
    inline bool isRunning(const T &f)
    {
        if(f.valid())
            return f.wait_for(std::chrono::nanoseconds(1)) != std::future_status::ready;
        else
            return false;
    }
    //阻塞式等待
    template<typename T>
    inline void waitForFinished(const T &f)
    {
        if(f.valid())
            return f.wait();
        else
            return;
    }
}
#endif //ZYTHREAD_H
