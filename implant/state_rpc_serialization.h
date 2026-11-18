#pragma once

#include <pthread.h>

class StateRpcSerialization {
public:
StateRpcSerialization() = default;
StateRpcSerialization(const StateRpcSerialization &) = delete;
StateRpcSerialization &operator=(const StateRpcSerialization &) = delete;

void lock() {
    pthread_mutex_lock(&mutex_);
}
void unlock() {
    pthread_mutex_unlock(&mutex_);
}

private:
pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
};

class StateRpcGuard {
public:
explicit StateRpcGuard(StateRpcSerialization *serialization)
    : serialization_(serialization) {
    serialization_->lock();
}
~StateRpcGuard() {
    serialization_->unlock();
}
StateRpcGuard(const StateRpcGuard &) = delete;
StateRpcGuard &operator=(const StateRpcGuard &) = delete;

private:
StateRpcSerialization *serialization_;
};
