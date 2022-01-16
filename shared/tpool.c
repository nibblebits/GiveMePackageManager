#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "tpool.h"
#include "log.h"
#include "vector.h"

struct thread_pool main_pool = {};

void *giveme_thread(void *arg)
{
    struct thread_pool *current_pool = arg;
    while (1)
    {
        struct queued_work *work = NULL;
        pthread_mutex_lock(&current_pool->queued_work_vec_lock);
        work = vector_back_ptr_or_null(current_pool->queued_work_vec);
        if (work)
        {
            vector_pop(current_pool->queued_work_vec);
        }

        pthread_mutex_unlock(&current_pool->queued_work_vec_lock);

        if (work)
        {
            // We have some popped work
            work->function(work);
            // Work is done lets delete the work
            free(work);
        }
        else if(current_pool->flags & GIVEME_THREAD_POOL_FLAG_END_THREADS_WHEN_NO_JOBS)
        {
            // No more jobs? We are done
            break;
        }
        sleep(1);
    }
}

void giveme_queue_work_for_pool(struct thread_pool *pool, QUEUED_WORK_FUNCTION function, void *private)
{
    struct queued_work *work = calloc(1, sizeof(struct queued_work));
    work->function = function;
    work->private = private;
    pthread_mutex_lock(&pool->queued_work_vec_lock);
    vector_push(pool->queued_work_vec, &work);
    pthread_mutex_unlock(&pool->queued_work_vec_lock);
}

void giveme_queue_work(QUEUED_WORK_FUNCTION function, void *private)
{
    giveme_queue_work_for_pool(&main_pool, function, private);
}

void giveme_thread_pool_start_for_pool(struct thread_pool *pool)
{
    for (size_t i = 0; i < pool->t_threads; i++)
    {
        pthread_create(&pool->threads[i], NULL, giveme_thread, pool);
    }
}

void giveme_thread_pool_start()
{
    giveme_thread_pool_start_for_pool(&main_pool);
}

int giveme_thread_pool_init_for_pool(struct thread_pool *pool, size_t _t_threads, int flags)
{
    pool->flags = flags;
    pool->t_threads = _t_threads;
    pool->threads = calloc(pool->t_threads, sizeof(pthread_t));
    pool->queued_work_vec = vector_create(sizeof(struct queued_work *));

    if (pthread_mutex_init(&pool->queued_work_vec_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize thread pool lock mutex\n");
        return -1;
    }

    return 0;
}
struct thread_pool *giveme_thread_pool_create(size_t _t_threads, int flags)
{
    struct thread_pool *pool = calloc(1, sizeof(struct thread_pool));
    int res = giveme_thread_pool_init_for_pool(pool, _t_threads, flags);
    if (res < 0)
    {
        return NULL;
    }

    return pool;
}

void giveme_thread_pool_join_and_free(struct thread_pool *pool)
{
    for (int i = 0; i < pool->t_threads; i++)
    {
        pthread_join(pool->threads[i], NULL);
    }
    free(pool);
}

int giveme_thread_pool_init(size_t _t_threads)
{
    return giveme_thread_pool_init_for_pool(&main_pool, _t_threads, 0);
}
