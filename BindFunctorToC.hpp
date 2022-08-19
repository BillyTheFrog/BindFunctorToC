//******************************************************************************
//* Copyright (c) 2022 Ezarkei                                                 *
//*                                                                            *
//* This document is under the MIT License                                     *
//******************************************************************************

#ifndef BINDFUNCTORTOC_HPP_
#define BINDFUNCTORTOC_HPP_

#if ((defined(__x86_64__) || defined(__i386__) || defined(__arm__)) && (defined(__linux__) || defined(__linux) || defined(linux) || defined(__unix__) || defined(__unix))) || (defined(WIN32) || defined(_WIN32) || defined(__WIN32__))

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#if defined(_DEBUG) || defined(DEBUG)
#error Requires release compilation (windows)
#endif
#define __win32__
#endif

#ifdef __win32__
#define __attribute__(__)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#endif

#include <type_traits>
#include <stdexcept>
#include <iostream>
#include <string>

#ifdef __win32__
#define __DCL__(_) ((typename decltype(_))(_))
#else
#define __DCL__(_) (_)
#endif
#define __FLG__ 0x21626e636967616d

template<typename R> struct __TTRf__ {
    explicit __TTRf__(void) noexcept = delete;
    using _R = R &;
};

template<typename> struct __BndFnctrTC__;
template<typename R, typename T, typename ...A> struct __BndFnctrTC__<R(T::*)(A...)> {
public:
    explicit __BndFnctrTC__(T &);
    ~__BndFnctrTC__(void) noexcept;

    R(*operator()(void) const noexcept)(A...);

    R(&_mppr)(__BndFnctrTC__<R(T::*)(A...)> &, typename __TTRf__<A>::_R...) noexcept = *&__MdmMppr__<>;

private:
    void __MplcDdrss__(void const *const);

    template<typename O = R> static typename std::enable_if<std::is_same<O, void>::value, void>::type __MdmMppr__(__BndFnctrTC__<R(T::*)(A...)> &, typename __TTRf__<A>::_R...) noexcept;
    template<typename O = R> static typename std::enable_if<!std::is_same<O, void>::value, O>::type __MdmMppr__(__BndFnctrTC__<R(T::*)(A...)> &, typename __TTRf__<A>::_R...) noexcept;
    static std::size_t __PgSzClcltr__(void) noexcept;
    static std::size_t __RwTmpltSzClcltr__(void) noexcept;

    static std::size_t const _flg, _pgSz, _rwTmpltSz, _sgmntSz;
    T &_trgt;
    void *_sgmnt;
};

template<typename> struct __CnstNxcptBstrct__;
template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...)> {
    explicit __CnstNxcptBstrct__(void) noexcept = delete;
    using _S = R(T::*)(A...);
};

template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) const> {
    explicit __CnstNxcptBstrct__(void) noexcept = delete;
    using _S = typename __CnstNxcptBstrct__<R(T::*)(A...)>::_S;
};

#if __cplusplus > 201402L

template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) noexcept> {
    explicit __CnstNxcptBstrct__(void) noexcept = delete;
    using _S = typename __CnstNxcptBstrct__<R(T::*)(A...)>::_S;
};

template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) const noexcept> {
    explicit __CnstNxcptBstrct__(void) noexcept = delete;
    using _S = typename __CnstNxcptBstrct__<R(T::*)(A...)>::_S;
};

#endif

template<typename T> class BindFunctorToC : public __BndFnctrTC__<typename __CnstNxcptBstrct__<decltype(&T::operator())>::_S> {
public:
    explicit BindFunctorToC(T &);
};

template<typename R, typename T, typename ...A> __attribute__((noinline, unused)) void __SzClcltrE__(void) noexcept;
template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<std::is_same<R, void>::value, void>::type __RwTmplt__(A...) noexcept;
template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<!std::is_same<R, void>::value, R>::type __RwTmplt__(A...) noexcept;

template<typename R, typename T, typename ...A> __BndFnctrTC__<R(T::*)(A...)>::__BndFnctrTC__(T &trgt) : _trgt{trgt} {
#ifdef __win32__
    (void const *const)(_rwTmpltSz + _pgSz);
    _sgmnt = VirtualAlloc(NULL, _sgmntSz, MEM_COMMIT, PAGE_READWRITE);
    if (!_sgmnt)
        throw std::runtime_error{std::string{"BindFunctorToC :: VirtualAlloc error :: "} + std::to_string(GetLastError())};
#else
    _sgmnt = mmap(nullptr, _sgmntSz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (MAP_FAILED == _sgmnt)
        throw std::runtime_error{std::string{"BindFunctorToC :: Mmap error :: "} + strerror(errno)};
#endif
    void const *const sgmnt{(void const *)__DCL__((&__RwTmplt__<R, T, A...>))};
    std::memcpy(_sgmnt, sgmnt, _rwTmpltSz);
    __MplcDdrss__(this);
#ifdef __win32__
    unsigned long dscrd;
    if (!VirtualProtect(_sgmnt, _sgmntSz, PAGE_EXECUTE_READ, &dscrd))
        throw std::runtime_error{std::string{"BindFunctorToC :: VirtualProtect error :: "} + std::to_string(GetLastError())};
#else
    if (mprotect(_sgmnt, _sgmntSz, PROT_EXEC | PROT_READ))
        throw std::runtime_error{std::string{"BindFunctorToC :: Mprotect error :: "} + strerror(errno)};
    __builtin___clear_cache((char *)_sgmnt, (char *)_sgmnt + _rwTmpltSz);
#endif
}

template<typename R, typename T, typename ...A> __BndFnctrTC__<R(T::*)(A...)>::~__BndFnctrTC__(void) noexcept {
#ifdef __win32__
    if (!VirtualFree(_sgmnt, 0, MEM_RELEASE)) {
#else
    if (munmap(_sgmnt, _sgmntSz)) {
#endif
        std::cerr << "BindFunctorToC :: Memory release failed :: Aborting" << std::endl;
        abort();
    }
}

template<typename R, typename T, typename ...A> R(*__BndFnctrTC__<R(T::*)(A...)>::operator()(void) const noexcept)(A...) {
    return (R(*)(A...))_sgmnt;
}

template<typename R, typename T, typename ...A> void __BndFnctrTC__<R(T::*)(A...)>::__MplcDdrss__(void const *const ddrss) {
    std::size_t const tht{(std::size_t const)ddrss};
    uint8_t *ffst{nullptr}, m{0};
    for (std::size_t i{0}, j{0}, k{0}; !ffst && _rwTmpltSz > i; ++i)
        if (j[(uint8_t*)&_flg] == i[(uint8_t*)_sgmnt]) {
            if (!j++)
                k = i;
            else if (sizeof(void *volatile const) <= j)
                ffst = (uint8_t*)_sgmnt + k;
        } else if (j)
            j = 0;
    if (ffst)
        std::memcpy(ffst, &tht, sizeof(void *volatile const));
    else {
        for (std::size_t i{0}; !ffst && _rwTmpltSz > i; ++i)
            for (uint8_t l{0}; !ffst && 8 > l; l += 4)
                for (std::size_t j{0}, k{0}; _rwTmpltSz > i + j + k && 7 > j; 2 == j ? (j += 2, k = l) : ++j)
                    if (!(j % 4 ? j % 2 ? (uint8_t{(uint8_t)(j[(uint8_t *)_sgmnt + i + k] << 4)} >> 4) == uint8_t{(uint8_t)((j / 4 ? 3 : 1)[(uint8_t *)&_flg] << 4)} >> 4 : (uint8_t{(uint8_t)(j[(uint8_t *)_sgmnt + i + k] << 4)} >> 4) == (j / 4 ? 3 : 1)[(uint8_t *)&_flg] >> 4 : j[(uint8_t *)_sgmnt + i + k] == (j / 2)[(uint8_t *)&_flg]))
                        j = 7;
                    else if (6 == j) {
                        ffst = (uint8_t *)_sgmnt + i;
                        m = l;
                    }
        if (ffst)
            for (std::size_t i{0}, k{0}; 7 > i; 2 == i ? (i += 2, k = m) : ++i)
                i % 4 ? ((i[ffst + k] >>= 4) <<= 4) |= i % 2 ? uint8_t{(uint8_t)((i / 4 ? 3 : 1)[(uint8_t *)&tht] << 4)} >> 4 : (i / 4 ? 3 : 1)[(uint8_t *)&tht] >> 4 : i[ffst + k] = (i / 2)[(uint8_t *)&tht];
    }
    if (!ffst)
        throw std::runtime_error{"BindFunctorToC :: Failed to resolve flag offset"};
}

template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<std::is_same<O, void>::value, void>::type __BndFnctrTC__<R(T::*)(A...)>::__MdmMppr__(__BndFnctrTC__<R(T::*)(A...)> &tht, typename __TTRf__<A>::_R... __flds__) noexcept {
    tht._trgt.operator()(std::forward<A>(__flds__)...);
}

template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<!std::is_same<O, void>::value, O>::type __BndFnctrTC__<R(T::*)(A...)>::__MdmMppr__(__BndFnctrTC__<R(T::*)(A...)> &tht, typename __TTRf__<A>::_R... __flds__) noexcept {
    return tht._trgt.operator()(std::forward<A>(__flds__)...);
}

template<typename R, typename T, typename ...A> void __SzClcltrE__(void) noexcept {
    __SzClcltrE__<R, T, A...>();
}

template<typename R, typename T, typename ...A> typename std::enable_if<std::is_same<R, void>::value, void>::type __RwTmplt__(A... __flds__) noexcept {
    void *volatile const __RwTmpltRmPtr__{(void *)__FLG__};
    __BndFnctrTC__<R(T::*)(A...)> &tht{*((__BndFnctrTC__<R(T::*)(A...)> *const)__RwTmpltRmPtr__)};
    tht._mppr(tht, __flds__...);
}

template<typename R, typename T, typename ...A> typename std::enable_if<!std::is_same<R, void>::value, R>::type __RwTmplt__(A... __flds__) noexcept {
    void *volatile const __RwTmpltRmPtr__{(void *)__FLG__};
    __BndFnctrTC__<R(T::*)(A...)> &tht{*((__BndFnctrTC__<R(T::*)(A...)> *const)__RwTmpltRmPtr__)};
    return tht._mppr(tht, __flds__...);
}

template<typename R, typename T, typename ...A> std::size_t __BndFnctrTC__<R(T::*)(A...)>::__PgSzClcltr__(void) noexcept {
#ifdef __win32__
    SYSTEM_INFO nf{};
    GetSystemInfo(&nf);
    return nf.dwPageSize;
#else
    return (std::size_t)sysconf(_SC_PAGESIZE);
#endif
}

template<typename R, typename T, typename ...A> std::size_t __BndFnctrTC__<R(T::*)(A...)>::__RwTmpltSzClcltr__(void) noexcept {
    if ((std::size_t)__DCL__((&__RwTmplt__<R, T, A...>)) > (std::size_t)&__SzClcltrE__<R, T, A...>) {
        std::cerr << "BindFunctorToC :: Memory order failed :: Unsupported architecture or compiler :: Aborting" << std::endl;
        abort();
    }
    return (std::size_t)&__SzClcltrE__<R, T, A...> - (std::size_t)__DCL__((&__RwTmplt__<R, T, A...>));
}

template<typename R, typename T, typename ...A> std::size_t const __BndFnctrTC__<R(T::*)(A...)>::_flg{(std::size_t)__FLG__};

template<typename R, typename T, typename ...A> std::size_t const __BndFnctrTC__<R(T::*)(A...)>::_pgSz{__PgSzClcltr__()};

template<typename R, typename T, typename ...A> std::size_t const __BndFnctrTC__<R(T::*)(A...)>::_rwTmpltSz{__RwTmpltSzClcltr__()};

template<typename R, typename T, typename ...A> std::size_t const __BndFnctrTC__<R(T::*)(A...)>::_sgmntSz{(_rwTmpltSz / _pgSz + 1) * _pgSz};

template<typename T> BindFunctorToC<T>::BindFunctorToC(T &trgt) : __BndFnctrTC__<typename __CnstNxcptBstrct__<decltype(&T::operator())>::_S>(trgt) {
}

#ifdef __win32__
#undef __win32__
#undef __attribute__
#endif
#undef __DCL__
#undef __FLG__

#else
#error Unknown architecture ; supports unix(-like) (x86_64, i386, arm) and windows (x64, x32)
#endif
#endif
