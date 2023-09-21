#include <iostream>
#include <string>
#include <typeinfo>
#include <cassert>

class Any {
private:
    class Holder {
    public:
        virtual ~Holder() {}
        virtual const std::type_info &Type() = 0;
        virtual Holder *clone() = 0;
    };
    template<class T>
    class PlaceHolder : public Holder {
    public:
        PlaceHolder(const T &val) : val_(val) {}
        const std::type_info &Type() { return typeid(T); }
        Holder *clone() { new PlaceHolder(val_); }

        T val_;        
    };

    Holder *context_;
public:
    Any() : context_(nullptr) {}
    ~Any() { delete context_; }
    template<class T>
    Any(const T &val) : context_(new PlaceHolder<T>(val)) {}
    Any(const Any &other) : context_(nullptr == other.context_ ? nullptr : other.context_->clone()) {}
    Any &swap(Any &other) { std::swap(context_, other.context_); }
    template<class T>
    Any &operator=(const T &val) {
        Any(val).swap(*this);
        return *this;
    }
    Any &operator=(const Any &other) {
        Any(other).swap(*this);
        return *this;
    }
    template<class T>
    T *get() {
        assert(typeid(T) == context_->Type());
        return &(dynamic_cast<PlaceHolder<T> *>(context_))->val_;
    }
};

class Test {
public:
    Test() { std::cout << "Test()" << std::endl; }
    Test(const Test& other) { std::cout << "Test(const Test &other)" << std::endl; }
    ~Test() { std::cout << "~Test()" << std::endl; }
};

int main() {

    {
        Test t;
        Any a(t);
    }
    while(true);
    //Any a = 10;
    //int *pa = a.get<int>();
    //std::cout << *pa << std::endl;
    //a = std::string("hello world");
    //std::string *sa = a.get<std::string>();
    //std::cout << *sa << std::endl;
    return 0;
}