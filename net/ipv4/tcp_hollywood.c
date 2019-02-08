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

void destroy_hollywood_output_message(struct hlywd_output_msg *msg) {
    kfree(msg);
}

void destroy_hollywood_output_queue(struct hlywd_output_queue *q) {
    while (q->head != NULL) {
        struct hlywd_output_msg *next = q->head->next;
        destroy_hollywood_output_message(q->head);
        q->head = next;
    }
}

void free_hollywood_output_message(struct hlywd_output_msg *msg, struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    msg->next = NULL;
    
    /* add to end of free queue */
    if (tp->hlywd_output_free_q.head == NULL) {
        tp->hlywd_output_free_q.head = msg;
        tp->hlywd_output_free_q.tail = msg;
    } else {
        tp->hlywd_output_free_q.tail->next = msg;
        tp->hlywd_output_free_q.tail = msg;
    }
}

struct hlywd_output_msg *get_hollywood_output_message(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct hlywd_output_msg *freeseg = tp->hlywd_output_free_q.head;

    if (freeseg != NULL) {
        tp->hlywd_output_free_q.head = freeseg->next;
        if (tp->hlywd_output_free_q.head == NULL) {
            tp->hlywd_output_free_q.tail = NULL;
        }
    } 

    return freeseg;
}

size_t enqueue_hollywood_output_msg(struct sock *sk, unsigned char __user *metadata, size_t write_size) {
    struct tcp_sock *tp = tcp_sk(sk);
    size_t metadata_size = 0;
    struct hlywd_output_msg *msg = get_hollywood_output_message(sk);
    if (msg == NULL) {
        msg = (struct hlywd_output_msg *) kmalloc(sizeof(struct hlywd_output_msg), GFP_KERNEL);
        if (msg == NULL) {
            printk("TCP Hollywood: could not kmalloc output message structure\n");
            return 0;
        }
    }

    /* set message metadata */
    copy_from_user((void *) &msg->substream, metadata, 1);

    printk("msg->substream %u\n", msg->substream);
    
    if (msg->substream == 2) {
        metadata_size = 9+2*sizeof(struct timespec);
        copy_from_user((void *) &msg->msg_id, metadata+1, 4);
        copy_from_user((void *) &msg->lifetime, metadata+5, sizeof(struct timespec));
        copy_from_user((void *) &tp->hlywd_playout, metadata+5+sizeof(struct timespec), sizeof(struct timespec));
        u32 dependency_msg_id;
        copy_from_user((void *) &dependency_msg_id, metadata+5+2*sizeof(struct timespec), 4);
        getnstimeofday(&msg->time_queued);
        msg->partially_acked = 0;
        msg->has_dependencies = 0;
        msg->replaced = 0;
        msg->incrtx_count = 0;
        msg->length = write_size - (9+2*sizeof(struct timespec));
        printk("Hollywood (PR): queued msg (id %u, lifetime %lld.%.9ld)\n", msg->msg_id, msg->lifetime.tv_sec, msg->lifetime.tv_nsec);
    } else {
        metadata_size = 1;
        msg->length = write_size - 1;
        msg->msg_id = 0;
        printk("Hollywood (PR): queued msg (id %u)\n", msg->msg_id);
    }
    
    msg->next = NULL;
            
    /* add to end of input queue */
    if (tp->hlywd_output_q.head == NULL) {
        tp->hlywd_output_q.head = msg;
        tp->hlywd_output_q.tail = msg;
    } else {
        tp->hlywd_output_q.tail->next = msg;
        tp->hlywd_output_q.tail = msg;
    }
    
    return metadata_size;
}

void dequeue_hollywood_output_queue(struct sock *sk, size_t bytes_acked) {
    struct tcp_sock *tp = tcp_sk(sk);

    while (bytes_acked > 0) {
        struct hlywd_output_msg *head = tp->hlywd_output_q.head;
        if (head == NULL) {
            break;
        }
        if (head->length <= bytes_acked) {
            printk("TCP Hollywood: fully ACK'd msg %u\n", head->msg_id);
            tp->hlywd_output_q.head = head->next;
            bytes_acked -= head->length;
            free_hollywood_output_message(head, sk);
        } else {
            printk("TCP Hollywood: partially ACK'd msg %u\n", head->msg_id);
            head->length -= bytes_acked;
            head->partially_acked = 1;
            bytes_acked = 0;
        }
    }
}

int check_message_liveness(struct sock *sk, struct timespec *current_time, struct timespec *owd, struct hlywd_output_msg *msg) {
    struct tcp_sock *tp = tcp_sk(sk);
     
    /* calculate sender queueing delay */
    struct timespec snd_q_delay = timespec_sub(*current_time, msg->time_queued);
    
    /* calculate total delay */
    struct timespec total_delay;
    total_delay = timespec_add(snd_q_delay, *owd);
    total_delay = timespec_add(total_delay, tp->hlywd_playout);
    
    printk("TCPH: checking liveness of msg %u .. snd_q_delay %lld.%.9ld owd %lld.%.9ld playout %lld.%.9ld total %lld.%.9ld lifetime %lld.%.9ld\n",
            msg->msg_id,
            snd_q_delay.tv_sec, snd_q_delay.tv_nsec,
            owd->tv_sec, owd->tv_nsec,
            tp->hlywd_playout.tv_sec, tp->hlywd_playout.tv_nsec,
            total_delay.tv_sec, total_delay.tv_nsec,
            msg->lifetime.tv_sec, msg->lifetime.tv_nsec);

    if (timespec_compare(&msg->lifetime, &total_delay) >= 0) {
        return 1;
    } else {
        return 0;
    }
}

void process_rtx(struct sock *sk, struct sk_buff *skb) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
    printk("TCP Hollywood (PR): retransmitting seq %u len %d\n", tcb->seq, skb->len);
    size_t offset = tcb->seq-tp->snd_una;
    size_t bytes_retrans = skb->len;
    struct hlywd_output_msg *msg = tp->hlywd_output_q.head;
    struct timespec owd_est;
    struct timespec current_time;
    
    /* set current time */
    getnstimeofday(&current_time);
    
    /* calculate one-way network delay */
    uint owd_nsec = ((tp->srtt_us >> 3) * 1000)/2; 
    owd_est.tv_sec = owd_nsec / 1000000000;
    owd_est.tv_nsec = owd_nsec % 1000000000;
    
    while (offset > 0) {
        if (msg->length <= offset) {
            msg = msg->next;
            offset -= msg->length;
        } else {
            bytes_retrans -= (msg->length - offset);
            offset = 0;
            printk("TCP Hollywood (PR): Partially retransmitting msg %u\n", msg->msg_id);
            msg = msg->next;
        }
    }
    
    /* msg points to first complete message being retransmitted */
    while (msg != NULL && bytes_retrans > 0) {
        if (msg->length <= bytes_retrans) {
            /* fully retransmitting this message -- has it expired? */
            printk("TCP Hollywood (PR): Fully retransmitting msg %u\n", msg->msg_id);
            if (!check_message_liveness(sk, &current_time, &owd_est, msg)) {
                printk("TCPH: msg %u expired\n", msg->msg_id);
                struct hlywd_output_msg *best_replacement = msg;
                struct hlywd_output_msg *candidate_replacement = msg->next;
                int min_incrtx_count = 0;
                while (candidate_replacement != NULL) {
                    if (candidate_replacement->length != msg->length) {
                        candidate_replacement = candidate_replacement->next;
                        continue;
                    }
                    if (!check_message_liveness(sk, &current_time, &owd_est, candidate_replacement)) {
                        printk(".. expired - moving on\n");
                        candidate_replacement = candidate_replacement->next;
                        continue;
                    }
                    if (candidate_replacement->incrtx_count == 0) {
                        printk(".. hasn't been retransmitted -- taking this one\n");
                        best_replacement = candidate_replacement;
                        break;
                    }
                    if (candidate_replacement->incrtx_count < min_incrtx_count || min_incrtx_count == 0) {
                        printk(".. has been retransmitted the least times to far -- best choice so far \n");
                        best_replacement = candidate_replacement;
                        min_incrtx_count = candidate_replacement->incrtx_count;
                        candidate_replacement = candidate_replacement->next;
                    }
                }
                printk("best replacement id %u\n", best_replacement->msg_id);
                if (best_replacement != msg) {
                    printk("TCPH: replacing msg %u with msg %u\n", msg->msg_id, best_replacement->msg_id);
                    best_replacement->incrtx_count++;
                }
            } else {
                printk("TCPH: msg %u live\n", msg->msg_id);
            }
            bytes_retrans -= msg->length;
            msg = msg->next;
        } else {
            printk("TCP Hollywood (PR): Partially retransmitting msg %u\n", msg->msg_id);
            bytes_retrans = 0;
        }
    }
}

/***************************************************************************************/

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
    
    printk("TCP Hollywood: enqueue_hollywood_input_segment [%u, len: %d (oo? %d)]\n", TCP_SKB_CB(skb)->seq, len, in_order);
    
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