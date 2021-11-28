#ifndef GIVEME_TPOOL_H
#define GIVEME_TPOOL_H

#include <stddef.h>

struct queued_work;
typedef int(*QUEUED_WORK_FUNCTION)(struct queued_work*);
struct queued_work
{
    QUEUED_WORK_FUNCTION function;
    union
    {
        void* private;
        int private_i;
        long private_l;
    };
    
};

void giveme_thread_pool_start();
int giveme_thread_pool_init(size_t _t_threads);
void giveme_queue_work(QUEUED_WORK_FUNCTION function, void *private);
#endif
