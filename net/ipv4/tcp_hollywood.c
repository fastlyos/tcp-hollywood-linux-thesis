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
 
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/tcp.h>
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
        destroy_hollywood_input_segment(q->head);
        q->head = next;
    }
}

void free_hollywood_input_segment(struct hlywd_input_segment *seg, struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    seg->next = NULL;
    
    /* add to end of free queue */
    if (tp->hlywd_input_free_q.head == NULL) {
        tp->hlywd_input_free_q.head = seg;
        tp->hlywd_input_free_q.tail = seg;
    } else {
        tp->hlywd_input_free_q.tail->next = seg;
        tp->hlywd_input_free_q.tail = seg;
    }
}

struct hlywd_input_segment *get_hollywood_input_segment(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct hlywd_input_segment *freeseg = tp->hlywd_input_free_q.head;

    if (freeseg != NULL) {
        tp->hlywd_input_free_q.head = freeseg->next;
        if (tp->hlywd_input_free_q.head == NULL) {
            tp->hlywd_input_free_q.tail = NULL;
        }
    } 

    return freeseg;
}

void enqueue_hollywood_input_segment(struct sock *sk, struct sk_buff *skb, size_t len, int in_order) {
    struct tcp_sock *tp = tcp_sk(sk);
    if (len == 0) {
        return;
    }
    
    printk("TCP Hollywood: enqueue_hollywood_input_segment [%u, len: %d (oo? %d)]\n", TCP_SKB_CB(skb)->seq, skb->len, in_order);
    
    struct hlywd_input_segment *seg = get_hollywood_input_segment(sk);
    if (seg == NULL) {
        seg = (struct hlywd_input_segment *) kmalloc(sizeof(struct hlywd_input_segment), GFP_KERNEL);
    }

    if (seg) {
        seg->sequence_number = TCP_SKB_CB(skb)->seq;
        seg->length = len;
        seg->offset = 0;
        
        if (!in_order) {
            seg->data = (void *) kmalloc(len, GFP_KERNEL);
            if (seg->data) {
                skb_copy_bits(skb, 0, seg->data, len);
            } else {
                printk("TCP Hollywood: could not enqueue incoming segment -- kmalloc failed for segment data\n");
            }
        } else {
            seg->data = NULL;
        }
        
        seg->next = NULL;
            
        /* add to end of input queue */
        if (tp->hlywd_input_q.head == NULL) {
            tp->hlywd_input_q.head = seg;
            tp->hlywd_input_q.tail = seg;
        } else {
            tp->hlywd_input_q.tail->next = seg;
            tp->hlywd_input_q.tail = seg;
        }
        sk->sk_data_ready(sk);
    } else {
        printk("TCP Hollywood: could not enqueue incoming segment -- kmalloc failed for metadata block\n");
    }
}

void dequeue_hollywood_input_queue(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct hlywd_input_segment *head = tp->hlywd_input_q.head;
    if (head != NULL) {
        //kfree(head->data);
        tp->hlywd_input_q.head = head->next;
        kfree(head);
    }
}