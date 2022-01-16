#ifndef GIVEME_TPOOL_H
#define GIVEME_TPOOL_H

#include <stddef.h>

struct queued_work;
typedef int (*QUEUED_WORK_FUNCTION)(struct queued_work *);
struct queued_work
{
    QUEUED_WORK_FUNCTION function;
    union
    {
        void *private;
        int private_i;
        long private_l;
    };
};

enum
{
    GIVEME_THREAD_POOL_FLAG_END_THREADS_WHEN_NO_JOBS = 0b00000001
};
struct thread_pool
{
    int flags;
    pthread_t *threads;
    size_t t_threads;
    struct vector *queued_work_vec;
    pthread_mutex_t queued_work_vec_lock;
};

void giveme_thread_pool_start();
int giveme_thread_pool_init(size_t _t_threads);
void giveme_queue_work(QUEUED_WORK_FUNCTION function, void *private);

struct thread_pool *giveme_thread_pool_create(size_t _t_threads, int flags);
void giveme_thread_pool_start_for_pool(struct thread_pool* pool);
void giveme_thread_pool_join_and_free(struct thread_pool* pool);
void giveme_queue_work_for_pool(struct thread_pool* pool, QUEUED_WORK_FUNCTION function, void *private);

#endif
