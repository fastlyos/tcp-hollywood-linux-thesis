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

void destroy_hollywood_input_segment(struct hlywd_input_segment *seg);
void destroy_hollywood_input_queue(struct hlywd_input_queue *q);
void enqueue_hollywood_input_segment(struct sock *sk, struct sk_buff *skb, size_t len, int in_order);
void dequeue_hollywood_input_queue(struct sock *sk);
void free_hollywood_input_segment(struct hlywd_input_segment *seg, struct sock *sk);
struct hlywd_input_segment *get_hollywood_input_segment(struct sock *sk);

#endif	/* _LINUX_HLYWD_H */