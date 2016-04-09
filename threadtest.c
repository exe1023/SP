#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#define NUM_HANDLER_THREADS 3

pthread_mutex_t request_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

pthread_cond_t got_request = PTHREAD_COND_INITIALIZER;

int main()
{
    pthread_mutex_lock(&request_mutex);

    printf("Locked!\n");

    pthread_mutex_unlock(&request_mutex);

    return 0;
}