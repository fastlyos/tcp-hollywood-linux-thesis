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
 * Output segment metadata
 */
 
struct hlywd_output_msg {
    u32 msg_id; /* ID of this message */
    size_t length; /* length of this message */
    struct timespec deadline; /* deadline of this message */
    u8 substream; /* ID of the substream of this message */

    /* flags */
    int partially_acked; /* set if this message has been partially ack'd */
    int has_dependencies; /* set if this message has dependencies */
    int is_replacement; /* set if this message can be replaced */
    
    int sent; /* number of times this message has been inconsistently retransmitted */
    
    struct hlywd_output_msg *next; /* next output message in queue */
};

/*
 * Output message queue
 */

struct hlywd_output_queue {
    struct hlywd_output_msg *head;
    struct hlywd_output_msg *tail;
};

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

void destroy_hollywood_output_message(struct hlywd_output_msg *msg);
void destroy_hollywood_output_queue(struct hlywd_output_queue *q);
void free_hollywood_output_message(struct hlywd_output_msg *msg, struct sock *sk);
struct hlywd_output_msg *get_hollywood_output_message(struct sock *sk);
void dequeue_hollywood_output_queue(struct sock *sk, size_t bytes_acked);
size_t enqueue_hollywood_output_msg(struct sock *sk, unsigned char __user *metadata, size_t write_size);
void process_tx(struct sock *sk, struct sk_buff *skb);

#endif	/* _LINUX_HLYWD_H */