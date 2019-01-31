/*
 * TCP Hollywood extensions
 *
 * Author: Stephen McQuistin <sm@smcquistin.uk>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_HLYWD_H
#define _LINUX_HLYWD_H

/*
 * Input segment metadata
 */
 
struct hlywd_input_segment {
    u32 sequence_number; /* sequence number of this segment */
    size_t length; /* total length of this segment */
    size_t offset; /* bytes read from this segment (remaining length = length - offset) */
    void *data; /* segment data */
    struct hlywd_input_segment *next; /* next input segment in queue */
};

/*
 * Input segment queue
 */

struct hlywd_input_queue {
    struct hlywd_input_segment *head;
    struct hlywd_input_segment *tail;
};

#endif	/* _LINUX_HLYWD_H */