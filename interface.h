#ifndef __LSTORE_CMSSW_INTERFACE_H
#define __LSTORE_CMSSW_INTERFACE_H
#include "statsd-client.h"
#include <time.h>
extern statsd_link * lfs_statsd_link;
#define STATSD_COUNT(name, count) if (lfs_statsd_link) { statsd_count(lfs_statsd_link, name, count, 1.0); }                                                                 
#define STATSD_TIMER_START(variable) time_t variable; time(& variable );
#define STATSD_TIMER_END(name, variable) time_t variable ## _end; if (lfs_statsd_link) { time(& variable ## _end); statsd_timing(lfs_statsd_link, name, (int) (difftime(variable ## _end, variable) * 1000.0)); }
#endif //__LSTORE_CMSSW_INTERFACE_H
