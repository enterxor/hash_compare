#undef __cplusplus
#include <stdint.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hash.h>
//
//  DPDK skeleton
//
#ifdef RTE_ARCH_X86
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
} __attribute__((__packed__));


#define SEQ_TO_REMEMBER 10
#define MAX_RETRANSMISSIONS 5
#define TCP_TIMEOUT 72
struct flow_retr_info
{
	uint32_t ring_seqs[SEQ_TO_REMEMBER];
	uint8_t retr_counts[SEQ_TO_REMEMBER];
	uint8_t head;
	uint8_t tail;
	uint64_t last_timestamp;
	uint32_t expected_seq;
};

uint8_t add_num_to_ring_buf(struct flow_retr_info * _struct, uint32_t _num)
{
	uint8_t result = _struct->head;
	_struct->ring_seqs[_struct->head] = _num;
	_struct->retr_counts[_struct->head] = 0;

	_struct->head = (_struct->head+1)%SEQ_TO_REMEMBER;
	if((_struct->head+1)%SEQ_TO_REMEMBER == _struct->tail )
	{
		_struct->tail = (_struct->tail+1)%SEQ_TO_REMEMBER;
	}
	return result;
}


#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

#define NUM_MBUFS 128
#define MBUF_CACHE_SIZE 0
#define BURST_SIZE 32
#define HASH_SIZE 1000000




struct rte_hash_parameters l3fwd_hash_params = {
		.name = "test_pcap_hash_0",
		.entries = HASH_SIZE,
		.key_len = sizeof(struct ipv4_5tuple),
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.socket_id = 0,
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};



/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count())
        return -1;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

/*
 * Setting up hash table
 */
static void
hash_setup(struct rte_hash** _hash_table)
{
    *_hash_table = rte_hash_create(&l3fwd_hash_params);
    if (*_hash_table == NULL)
            rte_exit(EXIT_FAILURE, "Unable to create the test_pcap hash on "
                            "socket 0\n");
}

/*
 * Unsetting hash table
 */
static void
hash_unset(struct rte_hash** _hash_table)
{
    /* Free records*/
    struct ipv4_5tuple *ikey;
    struct flow_retr_info *iretr_info_data;
    uint32_t iter=0;

    while(rte_hash_iterate(*_hash_table,&ikey,&iretr_info_data,&iter)!= ENOENT)
    {
		rte_hash_del_key(*_hash_table,&ikey);
		free(iretr_info_data);
		break;

    }

    /* Free resources. */
    rte_hash_free(*_hash_table);
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_main(void)
{
    const uint16_t nb_ports = rte_eth_dev_count();
    uint16_t port;
    uint16_t j;
    uint32_t total_packs =0;
    uint32_t dropped =0;
    uint32_t flows = 0;
    struct rte_hash* hash_table=0;
    hash_setup(&hash_table);
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    for (port = 0; port < nb_ports; port++)
    {
        if (rte_eth_dev_socket_id(port) > 0 &&
                rte_eth_dev_socket_id(port) !=
                (int)rte_socket_id())
        {
            printf("WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", port);

        }
    }
    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    /* Init Hash table */


    /* Run until the application is quit or killed. */
    /*
     * Receive packets on a port and forward them on the paired
     * port.
     */
    for (port = 0; port < nb_ports; port++)
    {
        uint16_t nb_rx;
        do {
            struct rte_mbuf *bufs[BURST_SIZE]; /* Pointers to RX mbuf structures. */
            struct rte_mbuf *bufs_tx[BURST_SIZE];  /* Pointers to mbuf which will be accepted. */
            uint32_t tx_count=0;

            /* Receiving bunch of packets  */
            nb_rx = rte_eth_rx_burst(port, 0,
                    bufs, BURST_SIZE);

            /* if no packets received, quit */
            if (unlikely(nb_rx == 0))
                break;

            /* save current timestamp to calculate tcp timeout*/
            uint64_t current_timestamp = bufs[0]->timestamp;

            /* For each packet do the check */
            for (j = 0; j < nb_rx; j++) {
                struct ether_hdr *eth_hdr;
                struct ipv4_hdr * ip_hdr;
                struct tcp_hdr * tcp_hdr;
                struct rte_mbuf *m = bufs[j];
                struct ipv4_5tuple key;
                struct flow_retr_info *retr_info_data;
                int lookup_rs =0;

                total_packs ++;

                /* Getting headers */
                eth_hdr = rte_pktmbuf_mtod(m,struct ether_hdr *);
                ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,sizeof(struct ether_hdr));
                tcp_hdr = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *,sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr));

                /* If packet is not ipv4 or not tcp, forward it */
                if(eth_hdr->ether_type!= 0x08 || ip_hdr->next_proto_id != 0x6)
                {
                    bufs_tx[tx_count++] = bufs[j];
                    continue;
                }

                /* Setting the key for hash table */
                key.ip_dst = ip_hdr->dst_addr;
                key.ip_src = ip_hdr->src_addr;
                key.port_dst = htons(tcp_hdr->dst_port);
                key.port_src = htons(tcp_hdr->src_port);

#ifdef DEBUG_OUTPUT
                printf("No. %d %d => %d %s\n",total_packs,key.port_src,key.port_dst,(tcp_hdr_->tcp_flags&0x2)?" SYN":"");
#endif

                /* Checking is key in hash table */
                if((lookup_rs=rte_hash_lookup_data(hash_table,&key,&retr_info_data))<0)
                {
                    if(tcp_hdr->tcp_flags&0x2)
                    {
                    	if(flows < HASH_SIZE)
                    	{
                    		retr_info_data = calloc(sizeof(struct flow_retr_info),1);

                    		/* Add key to hash table */
							rte_hash_add_key_data(hash_table,&key,retr_info_data);
							flows++;

							bufs_tx[tx_count++] = bufs[j];

							retr_info_data->last_timestamp = current_timestamp;
							//calculate next expected timestamp
							retr_info_data->expected_seq = htonl(tcp_hdr->sent_seq) + 1;
							//add current seq to ring buffer
							add_num_to_ring_buf(retr_info_data,htonl(tcp_hdr->sent_seq));
                    	}else
                    	{
                    		//iterate the table and delete timout sessions
                            struct ipv4_5tuple *ikey;
                            struct flow_retr_info *iretr_info_data;
                            uint32_t iter=0;

                            while(rte_hash_iterate(hash_table,&ikey,&iretr_info_data,&iter)!= ENOENT)
                            {
                            	// if we found expired session, delete its key, and add new instead
								if(current_timestamp - iretr_info_data->last_timestamp > TCP_TIMEOUT*1000000)
								{
									rte_hash_del_key(hash_table,&ikey);

									rte_hash_add_key_data(hash_table,&key,iretr_info_data);

									iretr_info_data->tail = iretr_info_data->head = 0;
									bufs_tx[tx_count++] = bufs[j];

									iretr_info_data->last_timestamp = current_timestamp;
									//calculate next expected timestamp
									iretr_info_data->expected_seq = htonl(tcp_hdr->sent_seq) + 1;
									//add current seq to ring buffer
									add_num_to_ring_buf(iretr_info_data,htonl(tcp_hdr->sent_seq));
									break;
								}
                            }
                            // if all entries are occupied - forward packet
                            if(iter == flows)
                            {
                            	bufs_tx[tx_count++] = bufs[j];
                            }
                    	}

                    }else
                    {
                        /* Drop packet */
                        /* Note that packets which we won`t send should bee freed manually*/
                        dropped++;
                        rte_pktmbuf_free(bufs[j]);

                    }
                }else
                {
                	//there we need to check that current seq equals expected
                	if(htonl(tcp_hdr->sent_seq) == retr_info_data->expected_seq)
                	{
						//forward key
						bufs_tx[tx_count++] = bufs[j];
						//remember last timestamp
						retr_info_data->last_timestamp = current_timestamp;
						//calculate next expected timestamp
						retr_info_data->expected_seq = htonl(tcp_hdr->sent_seq) + (htons(ip_hdr->total_length)- sizeof(struct ipv4_hdr) - ((tcp_hdr->data_off >> 4)*4));
						//if flags syn or fin set, increment seq
						if((tcp_hdr->tcp_flags&0x2)||(tcp_hdr->tcp_flags&0x1))
						{
							retr_info_data->expected_seq += 1;
						}
						//add current seq to ring buffer
						add_num_to_ring_buf(retr_info_data,htonl(tcp_hdr->sent_seq));
                	}else
                	{
                		//seq is not as expected
                		//retransmission or malicious packet
                		uint8_t i_ring =retr_info_data->tail;
                		for(;   i_ring!=retr_info_data->head;
                			    i_ring = (i_ring+1)% MAX_RETRANSMISSIONS )
                		{
                			if(retr_info_data->ring_seqs[i_ring] == htonl(tcp_hdr->sent_seq))
                			{
                				retr_info_data->retr_counts[i_ring] += 1;
                				if(retr_info_data->retr_counts[i_ring]>MAX_RETRANSMISSIONS )
                				{
                					// too much retransmissions - remove flow from hash table
                					// drop packet
                					rte_hash_del_key(hash_table,&key);
                					flows --;
                					free(retr_info_data);
                					retr_info_data = NULL;
                                    dropped++;
                                    rte_pktmbuf_free(bufs[j]);
                					break;
                				}
                				// forward packet, remember timestamp
        						bufs_tx[tx_count++] = bufs[j];
        						retr_info_data->last_timestamp = current_timestamp;
        						//next excepted seq remains the same
                				break;
                			}
                		}
                		//drop packet if its seq was not found in the ring buffer
                		if(retr_info_data!= NULL && i_ring==retr_info_data->head)
                		{

							dropped++;
							rte_pktmbuf_free(bufs[j]);
                		}
                	}

                }
            }
            /* Send burst of acepted TX packets, to out. */
            /* Note that packets which send with rte_eth_tx_burst frees automatically */
            const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                    bufs_tx, tx_count);
        } while (nb_rx);
        printf("Total handled: %d\n"
        	   "Accepted: %d\n"
        	   "Dropped: %d\n"
        	   "Flows registered: %d",total_packs,total_packs-dropped,dropped,flows);


        hash_unset(&hash_table);

        rte_eth_dev_stop(port);
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "Error: ports not found\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    for (portid = 0; portid < nb_ports; portid++)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                    portid);

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the master core only. */
    lcore_main();


    return 0;
}
