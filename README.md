DEPRECATED ; NEW SOFTWARE IS MAINTAINED AT https://gitlab.com/Ezarkei/BindToC

# BindFunctorToC

Allows binding of a C++ object instance's functor (operator()) to a C-style function pointer.

## Description

Sometimes we need to bind a non static C++ method to a C library, through callbacks of C-style function pointer.
This can often be problematic, as C++ method pointers require an instance to be run on during the call, and we cannot modify the C library's code.
Through the use of a static instance, we can manage to pass a C-style function pointer with the matching signature, but then we can only have one instance of our C++ class for callbacks which is not desired.

Here any object's operator() will be refered to as its functor. It is not exactly adequate, but let's not be pedant and accept the lack of correctness regarding this naming.

This project allows to bind a C++ object's functor to a C-style function pointer through the use of runtime code writting.
When an instance of the binder class is created, it will allocate N memory page(s) (platform dependant, will calculate the required size, usually 1) and then proceed to copy some dummy code to that mapped memory area.
This dummy code will then be inspected and modified to have it's matching instance's address written inside, thus when called it can grab it's instance's target address and then call it.

This process is stable and works on the following platforms and environments:
- Unis-like systems (x86_64, i386, arm)
- Windows (x64, x32)
- C++ 11, 14, 17, +

The functor's signature will be automatically deduced and resolved, this process supports 0 to n arguments of any type, as well as void or any return type.
Then the C-style function pointer signature will be created matching the functor's, thus allowing a simple code writting for the user.

/!\ The C-style function pointer is ONLY available during its binder's lifetime, it will be destroyed uppon its binder own destruction.

## Getting started

### Examples

Simple
```cpp
    Object instance{}; //Create an instance
    BindFunctorToC<Object> binder{instance}; //Create a binder on that instance
    void(*fPtr)(void){binder()}; //Get the C-style function pointer from the binder, here the signature is void(*)(void)
    fPtr(); //Call the C-style function pointer
```

Detailed
```cpp
#include "BindFunctorToC.hpp"

#include <iostream>

struct Foo {
    int operator()(std::string const &other) const noexcept { //This is our functor, the "entry point" to our object from the C-style function pointer call
	return Bar(other); //Here this functor simply forwards to a method
    }
    int Bar(std::string const &other) const noexcept { //This method is non-static and will use an object's member: _str
	std::cout << _str << ' ' << other << std::endl; //Beeing able to access _str here clearly shows that it's not a trick, we have a direct access to 'this'
	return 0;
    }
    std::string const _str{"default"};
};

static void CallBack(int(*callback)(std::string const &)) noexcept { //This is the kind of use case we want to be able to accomplish, a simple C-style function pointer is passed as parameter but it will effectively call a non-static method on an object
    callback("world"); //Here we will call foo1 instance's operator(), hence foo1's 'Bar' method
}

int main(void) {
    Foo foo1{"hello"}, foo2{"foo"}; //First we declare 2 instances of Foo, with 2 different member values so we can distinguish them well
    BindFunctorToC<Foo> binder1{foo1}, binder2{foo2}; //For every instance a binder is needed
    int(*ptr)(std::string const &){binder1()}; //We then construct a C-style function pointer with Foo's operator() signature and initialize it to binder1 function by calling binder1's operator()
    CallBack(ptr); //Here we will pass our C-style function pointer to the C api which may need it as a callback
    return binder2()("bar"); //Proof that we work on instances, first the operator() will get the C-style function pointer, then we call it and return its value to show the signatures deduction works
}
```

### Installing

This solution is provided as a one header solution, only BindFunctorToC.hpp is needed, you can copy it to your sources and include it in your code.

## Issues

Under ARM based CPUs we can meet an issue, if the CPU keeps the binder's instructions running at a critical time, it will NOT refresh its cache as code is not known to change at runtime from the CPU point of view, even if it has been modified.
This issue is addressed by calling a compiler builtin which in turn will do an inline assembly syscall to trigger the CPU refresh on the modified memory area.

Return parameter CANNOT be a C++ type calling a copy constructor, as we go through the JITed code, this will most likely cause undefined behaviour due to addresses beeing related to one another.
This issue is addressed by, as a user, returning a raw pointer on the specific object if you at all need to return an object and not a primitive.

## Authors

Ezarkei

## License

This project is Licensed under the MIT License - see the LICENSE.md file for details.
