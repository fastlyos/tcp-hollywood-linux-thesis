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
 
#include <linux/hollywood.h>

void destroy_hollywood_input_segment(struct hlywd_input_segment *seg) {
    if (seg->data != NULL) {
        kfree(seg->data);
    }
    kfree(seg);
}

void destroy_hollywood_input_queue(struct hlywd_input_queue *q) {
    while (q->head != NULL) {
        struct hlywd_input_segment *next = q->head->next;
        destroy_hollywood_input_segment(q->head->next);
        q->head = next;
    }
}

void enqueue_hollywood_input_segment(struct sock *sk, struct sk_buff *skb, int in_order) {
    struct hlywd_input_segment *seg = (struct hlywd_input_segment *) kmalloc(sizeof(struct hlywd_input_segment), GFP_KERNEL);
    if (seg) {
        struct tcp_sock *tp = tcp_sk(sk);
        
        seg->sequence_number = TCP_SKB_CB(skb)->seq;
        seg->length = skb->len;
        seg->offset = 0;

        if (!in_order) {
            seg->data = (void *) kmalloc(skb->len, GFP_KERNEL);
            if (seg->data) {
                skb_copy_bits(skb, 0, seg->data, skb->len);
            } else {
                printk("TCP Hollywood: could not enqueue incoming segment -- kmalloc failed for segment data\n");
            }
        } else {
            seg->data = NULL;
        }
        
        seg->next = NULL;
            
        /* add to end of input queue */
        if (tp->hlywd_input_q->head == NULL) {
            tp->hlywd_input_q->head = seg;
            tp->hlywd_input_q->tail = seg;
        } else {
            tp->hlywd_input_q->tail->next = seg;
            tp->hlywd_input_q->tail = seg;
        }
        sk->sk_data_ready(sk);
    } else {
        printk("TCP Hollywood: could not enqueue incoming segment -- kmalloc failed for metadata block\n");
    }
}

void dequeue_hollywood_input_queue(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct hlywd_input_segment *head = tp->hlywd_input_q->head
    if (head != NULL) {
        kfree(head->data);
        tp->hlywd_input_q->head = head->next;
        kfree(head);
    }
}