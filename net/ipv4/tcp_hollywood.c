/*
 * TCP Hollywood extensions
 *
 * Author: Stephen McQuistin <sm@smcquistin.uk>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * COBS encoding (cobs_encode function)
 *
 * Author: Jacques Fortier
 *
 *    Copyright 2011, all rights reserved. Redistribution and use in source
 *    and binary forms are permitted, with or without modification.
 */
 
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/hollywood.h>

/* Stuffs "length" bytes of data at the location pointed to by
 * "input", writing the output to the location pointed to by
 * "output". Returns the number of bytes written to "output".
 *
 * Remove the "restrict" qualifiers if compiling with a
 * pre-C99 C dialect.
 */
size_t cobs_encode(const uint8_t *input, size_t length, uint8_t *output)
{
    size_t read_index = 0;
    size_t write_index = 1;
    size_t code_index = 0;
    uint8_t code = 1;

    while(read_index < length)
    {
        if(input[read_index] == 0)
        {
            output[code_index] = code;
            code = 1;
            code_index = write_index++;
            read_index++;
        }
        else
        {
            output[write_index++] = input[read_index++];
            code++;
            if(code == 0xFF)
            {
                output[code_index] = code;
                code = 1;
                code_index = write_index++;
            }
        }
    }

    output[code_index] = code;

    return write_index;
}

uint8_t *generate_padding_message(struct sock *sk, size_t padding_length) {
    struct tcp_sock *tp = tcp_sk(sk);
    int cobs_added_bytes = padding_length/257;
    uint8_t *padding_message_encoded = (uint8_t *) kmalloc(padding_length, GFP_KERNEL);
    padding_message_encoded[0] = '\0';
    size_t encoded_len = cobs_encode(tp->hlywd_padding_buffer, padding_length-3-cobs_added_bytes, padding_message_encoded+1);
    padding_message_encoded[encoded_len+1] = '\0';
    return padding_message_encoded;
}

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
    
    if (msg->substream == 2) {
        metadata_size = 9+sizeof(struct timespec);
        copy_from_user((void *) &msg->msg_id, metadata+1, 4);
        copy_from_user((void *) &msg->deadline, metadata+5, sizeof(struct timespec));
        u32 dependency_msg_id;
        copy_from_user((void *) &dependency_msg_id, metadata+5+sizeof(struct timespec), 4);
        /* dependency management */
        if (dependency_msg_id != msg->msg_id) {
            struct hlywd_output_msg *dep_msg = tp->hlywd_output_q.head;
            while (dep_msg != NULL) {
                if (dep_msg->substream == 2 && dep_msg->msg_id == dependency_msg_id) {
                    dep_msg->has_dependencies = 1;
                }
                dep_msg = dep_msg->next;
            }
            if (dependency_msg_id > tp->hlywd_highest_dep_id) {
                tp->hlywd_highest_dep_id = dependency_msg_id;
            }
        }
        msg->partially_acked = 0;
        msg->has_dependencies = 0;
        msg->is_replacement = 0;
        msg->sent = 0;
        msg->length = write_size - (9+sizeof(struct timespec));
        //printk("Hollywood (PR): queued msg (id %u, deadline %lld.%.9ld, length %d)\n", msg->msg_id, msg->deadline.tv_sec, msg->deadline.tv_nsec, msg->length);
    } else {
        metadata_size = 1;
        msg->length = write_size - 1;
        msg->msg_id = 0;
        //printk("Hollywood (PR): queued msg (id %u)\n", msg->msg_id);
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
            //printk("TCP Hollywood: fully ACK'd msg %u\n", head->msg_id);
            tp->hlywd_output_q.head = head->next;
            bytes_acked -= head->length;
            free_hollywood_output_message(head, sk);
        } else {
            //printk("TCP Hollywood: partially ACK'd msg %u\n", head->msg_id);
            head->length -= bytes_acked;
            head->partially_acked = 1;
            bytes_acked = 0;
        }
    }
}

struct timespec check_message_liveness(struct sock *sk, struct timespec *current_time, struct timespec *owd, struct hlywd_output_msg *msg, int *expired) {     
    /* estimate arrival time */
    struct timespec arrival_est = timespec_add(*current_time, *owd);

    //printk("TCPH: checking liveness of msg %u .. current_time %lld.%.9ld owd %lld.%.9ld arrival_est %lld.%.9ld deadline %lld.%.9ld\n",
    //        msg->msg_id,
    //        current_time->tv_sec, current_time->tv_nsec,
    //        owd->tv_sec, owd->tv_nsec,
    //        arrival_est.tv_sec, arrival_est.tv_nsec,
    //        msg->deadline.tv_sec, msg->deadline.tv_nsec);

    if (timespec_compare(&arrival_est, &msg->deadline) > 0) {
        *expired = 1;
        return timespec_sub(arrival_est, msg->deadline);
    } else {
        *expired = 0;
        return timespec_sub(msg->deadline, arrival_est);
    }
}

void process_tx(struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL || skb->len <= 0) {
        return;
    }
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
    if (tp == NULL || tcb == NULL) {
        return;
    }
    
    //printk("TCP Hollywood (PR): transmitting seq %u len %d\n", tcb->seq, skb->len);
    
    int offset = tcb->seq-tp->snd_una;
    int bytes_trans = skb->len;
    struct hlywd_output_msg *msg = tp->hlywd_output_q.head;
    struct timespec owd_est;
    struct timespec current_time;
    int bytes_to_msg = 0;

    if (msg == NULL) {
        return;
    }
    
    /* set current time */
    getnstimeofday(&current_time);
    
    /* calculate one-way network delay */
    uint owd_nsec = ((tp->srtt_us >> 3) * 1000)/2; 
    owd_est.tv_sec = owd_nsec / 1000000000;
    owd_est.tv_nsec = owd_nsec % 1000000000;

    while (offset > 0 && msg != NULL) {
        if (msg->length <= offset) {
            /* message is entirely in offset (not sent) */
            msg = msg->next;
            offset -= msg->length;
        } else {
            /* message is _partially_ in offset -- some of it is sent */
            bytes_trans -= (msg->length - offset);
            bytes_to_msg += (msg->length - offset);
            offset = 0;
            msg->sent = 1;
            msg = msg->next;
        }
    }
        
    /* msg should now point to the first complete message being sent */
    while (bytes_trans > 0 && msg != NULL) {
        if (msg-> length <= bytes_trans && msg->sent == 1) {
            /* msg is being transmitted in full -- should be checked for liveness */
            int msg_expired = 0;
            struct timespec timediff = check_message_liveness(sk, &current_time, &owd_est, msg, &msg_expired);
            if ((msg->has_dependencies == 1 && msg->is_replacement == 0) || (msg->msg_id <= tp->hlywd_highest_dep_id && msg->is_replacement == 0)) {
                msg->sent = 1;
            } else if ((msg_expired == 1 && msg->sent == 0) || msg->sent == 1) {
                /* msg has expired -- need to find a replacement */
                /* best unexpired candidate */
                struct hlywd_output_msg *best_live = NULL;
                struct timespec          best_live_timediff;
                int                      bytes_to_best_live_replacement = 0;
                /* best expired candidate */
                struct hlywd_output_msg *best_expired = NULL;
                struct timespec          best_expired_timediff;
                int                      bytes_to_best_expired_replacement = 0;
                /* candidate replacement search */
                struct hlywd_output_msg *candidate_replacement = tp->hlywd_output_q.head;
                int                      bytes_to_candidate = 0;
                while (candidate_replacement != NULL) {
                    int length_diff = msg->length-candidate_replacement->length;
                    if (length_diff == 0 || (length_diff >= 4 && length_diff <= 1500)) {
                        int candidate_replacement_expired = 0;
                        struct timespec replacement_timediff = check_message_liveness(sk, &current_time, &owd_est, candidate_replacement, &candidate_replacement_expired);
                        if (!candidate_replacement_expired) {
                            /* candidate replacement is live */
                            if (best_live == NULL || timespec_compare(&replacement_timediff, &best_live_timediff) < 0) {
                                best_live = candidate_replacement;
                                best_live_timediff = replacement_timediff;
                                bytes_to_best_live_replacement = bytes_to_candidate;
                            }
                        } else {
                            /* candidate replacement is expired */
                            if (best_live == NULL && (best_expired == NULL || timespec_compare(&replacement_timediff, &best_expired_timediff) < 0)) {
                                best_expired = candidate_replacement;
                                best_expired_timediff = replacement_timediff;
                                bytes_to_best_expired_replacement = bytes_to_candidate;
                            }
                        }
                    }
                    bytes_to_candidate += candidate_replacement->length;
                    candidate_replacement = candidate_replacement->next;
                }
                /* identify replacement */
                struct hlywd_output_msg *replacement_msg = NULL;
                int bytes_to_replacement = 0;
                if (best_live != NULL) {
                    replacement_msg = best_live;
                    bytes_to_replacement = bytes_to_best_live_replacement;
                } else {
                    replacement_msg = best_expired;
                    bytes_to_replacement = bytes_to_best_expired_replacement;
                }
                /* swap replacement into msg */
                if (replacement_msg != NULL) {
                    /* swap metadata */
                    replacement_msg->sent = 1;
                    msg->msg_id = replacement_msg->msg_id;
                    msg->deadline = replacement_msg->deadline;
                    msg->substream = replacement_msg->substream;
                    msg->has_dependencies = replacement_msg->has_dependencies;
                    msg->is_replacement = 1;
                    msg->sent = 1;
                    void *replacement_msg_data = (void *) kmalloc(msg->length, GFP_KERNEL);
                    if (replacement_msg_data) {
                        struct sk_buff *replacement_skb = tcp_write_queue_head(sk);
                        /* fast forward to skb containing start of replacement msg */
                        while (replacement_skb->len <= bytes_to_replacement) {
                            bytes_to_replacement -= replacement_skb->len;
                            if (!tcp_skb_is_last(sk, replacement_skb)) {
                                replacement_skb = tcp_write_queue_next(sk, replacement_skb);
                            }
                        }
                        int bytes_to_copy = replacement_msg->length;
                        while (bytes_to_copy > 0) {
                            int bytes_can_copy = min(bytes_to_copy, replacement_skb->len-bytes_to_replacement);
                            skb_copy_bits(replacement_skb, bytes_to_replacement, replacement_msg_data+(replacement_msg->length-bytes_to_copy), bytes_can_copy);
                            bytes_to_replacement = 0;
                            bytes_to_copy -= bytes_can_copy;
                            if (tcp_skb_is_last(sk, replacement_skb)) {
                                break;
                            } else {
                                replacement_skb = tcp_write_queue_next(sk, replacement_skb);
                            }
                        }    
                        skb_store_bits(skb, bytes_to_msg, replacement_msg_data, replacement_msg->length);
                        kfree(replacement_msg_data);       
                        int length_diff = msg->length-replacement_msg->length;
                        if (length_diff != 0) {
                            uint8_t *padding_msg = generate_padding_message(sk, length_diff);
                            skb_store_bits(skb, bytes_to_msg+replacement_msg->length, padding_msg, length_diff);
                            kfree(padding_msg);
                        } 
                    }
                }
            }
        } else {
            msg->sent = 1;
        }
        bytes_trans -= msg->length;
        bytes_to_msg += msg->length;
        msg = msg->next;
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
    
    //printk("TCP Hollywood: enqueue_hollywood_input_segment [%u, len: %d (oo? %d)]\n", TCP_SKB_CB(skb)->seq, len, in_order);
    
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