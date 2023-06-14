#pragma once
#include <algorithm>
#include <cstring>
#include <istream>
#include <ostream>

static unsigned char ALL_ISS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05};
static unsigned char OUR_MAC[6] = {0x00, 0x0c, 0x29, 0x6f, 0x14, 0xbf};
//static unsigned char OUR_IP_ADDRESS[4] = {0x0a, 0x64, 0x00, 0x01};
//static unsigned char DUT_IP_ADDRESS[4] = {0x0a, 0x64, 0x00, 0x00};

//static unsigned char SYS_ID[6] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01};
//static unsigned char DUT_SYS_ID[7] = {0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00};
//static unsigned char AREA[4] = {0x03, 0x49, 0x00, 0x01};
static unsigned char EXTENDED_CIRCUIT_ID[4] = {0x00, 0x00, 0x00, 0x01};
//static unsigned char SOURCE_ID[7] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00}; <---- rework as SYS_ID + 1
static unsigned char START_LSP_ID[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static unsigned char END_LSP_ID[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//static unsigned char OUR_LSP_ID[8] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
//static unsigned char OUR_LSP_SEQ[4] = {0x00, 0x00, 0x00, 0x01};

//static unsigned char OUR_LSP_LT[2] = {0x04, 0x4c};
//static unsigned char OUR_HOSTNAME[11] = {0x69, 0x73, 0x69, 0x73, 0x2d, 0x6d, 0x6f, 0x63, 0x6b, 0x65, 0x72};

enum level { l1 = 0x1, l2 = 0x2, l12 = 0x3 };

enum packet { p2p_hello = 17, l2_lsp = 20, l2_csnp = 25, l2_psnp = 27 };

enum state { down = 2, init = 1, up = 0 };

/*
     0            8            16                       31
     ┌────────────┬────────────┬────────────┬────────────┐
     │  IRPD      │ Length     │ Version ID │ ID Length  │
     │            │ Indicator  │            │            │
     ├────────────┼────────────┼────────────┼────────────┤
     │  PDU Type  │  Version   │  Reserved  │ Max Area   │
     │            │            │            │ Addresses  │
     └────────────┴────────────┴────────────┴────────────┘

*/

class isis_header {
    public:
	isis_header() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		irpd(0x83);
		version_id(1);
		version(1);
	}

	void irpd(unsigned char n) { rep_[0] = n; }
	void length_indicator(unsigned char n) { rep_[1] = n; }
	void version_id(unsigned char n) { rep_[2] = n; }
	void pdu_type(unsigned char n) { rep_[4] = n; }
	void version(unsigned char n) { rep_[5] = n; }

	unsigned int pdu_type() const { return (unsigned int)rep_[4]; };
	unsigned char length_indicator() const { return rep_[1]; };
	unsigned short size() const { return sizeof(rep_); };

	friend std::istream& operator>>(std::istream& is, isis_header& header) { return is.read(reinterpret_cast<char*>(header.rep_), 8); }

	friend std::ostream& operator<<(std::ostream& os, const isis_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 8);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[8];
};

/*

  0            8            16                       31
  ┌────────────┬──────────────────────────────────────┐
  │  Circuit   │           System ID                  │
  │  Type      │                                      │
  ├────────────┴─────────────────────────┬────────────┤
  │             System ID                │ Holding    │
  │                                      │ Timer      │
  ├────────────┬─────────────────────────┼────────────┤
  │ Holding    │ PDU Length              │ Local      │
  │ Timer      │                         │ Circuit ID │
  └────────────┴─────────────────────────┴────────────┘

*/

class isis_hello_header {
    public:
	isis_hello_header() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		circuit_type(l2);
		//system_id(SYS_ID);
		holding_timer(30);
	}

	void circuit_type(unsigned char n) { rep_[0] = n; }
	void system_id(unsigned char* n) { std::memcpy(&rep_[1], n, 6); }
	void holding_timer(unsigned short n) { encode(7, 8, n); }
	void pdu_length(unsigned short n) { encode(9, 10, n); }
	void local_circuit_id(unsigned char n) { rep_[11] = n; }

	unsigned char* system_id() { return &rep_[1]; };
	unsigned short holding_timer() const { return decode(7, 8); };
	unsigned short pdu_length() const { return decode(9, 10); };

	friend std::istream& operator>>(std::istream& is, isis_hello_header& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 12);
	}

	friend std::ostream& operator<<(std::ostream& os, const isis_hello_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 12);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[12];
};

/* TLVs */

/*

  0            8            16                       31
  ┌────────────┬─────────────┬───────────┬────────────┐
  │  Type      │  Length     │ Adjacency │Extended    │
  │            │             │ State     │Local Cir Id│
  ├────────────┴─────────────┴───────────┼────────────┘
  │   Extended Local Circuit ID          │
  │                                      │
  └──────────────────────────────────────┘

*/

class tlv_240 {
    public:
	tlv_240() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(240);
		tlv_length(5);
		adjacency_state(down);
		ext_local_circuit_id(EXTENDED_CIRCUIT_ID);
	}
	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void adjacency_state(unsigned char n) { rep_[2] = n; }
	void ext_local_circuit_id(unsigned char* n) { std::memcpy(rep_ + 3, n, sizeof(EXTENDED_CIRCUIT_ID)); }

	unsigned char tlv_type() const { return rep_[0]; };
	unsigned char tlv_length() const { return rep_[1]; };
	unsigned char adjacency_state() const { return rep_[2]; };
	unsigned char* ext_local_circuit_id() { return &rep_[3]; };

	friend std::istream& operator>>(std::istream& is, tlv_240& header) { return is.read(reinterpret_cast<char*>(header.rep_), 7); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_240& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 7);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[7];
};

/*

  0            8            16                       31
  ┌────────────┬─────────────┬───────────┬────────────┐
  │  Type      │  Length     │ Adjacency │Extended    │
  │            │             │ State     │Local Cir Id│
  ├────────────┴─────────────┴───────────┼────────────┤
  │   Extended Local Circuit ID          │ Neighbor   │
  │                                      │ System ID  │
  ├──────────────────────────────────────┴────────────┤
  │          Neighbor System ID                       │
  │                                                   │
  ├────────────┬──────────────────────────────────────┤
  │ Neighbor   │   Neighbor Extended Local Circuit ID │
  │ System ID  │                                      │
  ├────────────┼──────────────────────────────────────┘
  │ Neighbor Ex│
  │ Loc Cir ID │
  └────────────┘

*/

class tlv_240_ext {
    public:
	enum { down = 2, init = 1, up = 0 };

	tlv_240_ext() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(240);
		tlv_length(15);
		adjacency_state(init);
	}
	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void adjacency_state(unsigned char n) { rep_[2] = n; }
	void ext_local_circuit_id(unsigned char* n) { std::memcpy(rep_ + 3, n, sizeof(EXTENDED_CIRCUIT_ID)); }
	void neighbor_sysid(unsigned char* n) { std::memcpy(rep_ + 7, n, 6); }
	void ext_neighbor_local_circuit_id(unsigned char* n) { std::memcpy(rep_ + 13, n, sizeof(EXTENDED_CIRCUIT_ID)); }

	unsigned char tlv_type() const { return rep_[0]; };
	unsigned char tlv_length() const { return rep_[1]; };
	unsigned char adjacency_state() const { return rep_[2]; };
	unsigned char* neighbor_sysid() { return &rep_[7]; };
	unsigned char* ext_local_circuit_id() { return &rep_[3]; };
	unsigned char* ext_neighbor_local_circuit_id() { return &rep_[13]; };

	friend std::istream& operator>>(std::istream& is, tlv_240_ext& header) { return is.read(reinterpret_cast<char*>(header.rep_), 17); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_240_ext& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 17);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[17];
};

/*
  0            8            16                       31
  ┌───────────────────────────────────────────────────┐
  │      Destination MAC                              │
  │                                                   │
  ├─────────────────────────┬─────────────────────────┤
  │  Destination MAC        │    Source MAC           │
  │                         │                         │
  ├─────────────────────────┴─────────────────────────┤
  │          Source MAC                               │
  │                                                   │
  ├─────────────────────────┬────────────┬────────────┤
  │   Length                │  DSAP      │  SSAP      │
  │                         │            │            │
  ├────────────┬────────────┴────────────┴────────────┘
  │ Control    │
  │ Field      │
  └────────────┘
*/

class eth_header {
	/* +llc  */
    public:
	eth_header() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		destination(ALL_ISS);
		source(OUR_MAC);
		dsap(0xfe);
		ssap(0xfe);
		control_field(0x03);
	}

	// void destination(unsigned char *n) { encode_array(n, sizeof(n), 0);}
	// void source(unsigned char *n) { encode_array(n, sizeof(n), 6);}
	void destination(unsigned char* n) { std::memcpy(&rep_[0], n, sizeof(ALL_ISS)); }
	void source(unsigned char* n) { std::memcpy(&rep_[6], n, sizeof(OUR_MAC)); }
	void length(unsigned short n) { encode(12, 13, n); }
	void dsap(unsigned char n) { rep_[14] = n; }
	void ssap(unsigned char n) { rep_[15] = n; }
	void control_field(unsigned char n) { rep_[16] = n; }

	unsigned short length() const { return decode(12, 13); };
	unsigned char* dmac() { return &rep_[0]; };

	friend std::istream& operator>>(std::istream& is, eth_header& header) { return is.read(reinterpret_cast<char*>(header.rep_), 17); }

	friend std::ostream& operator<<(std::ostream& os, const eth_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 17);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	void encode_array(unsigned char* n, int size, int position) {
		for (int i = 0; i < size; ++i) {
			rep_[position + i] = n[size + i];
		}
	}

	unsigned char rep_[17];
};

/*

  0            8            16                       31
  ┌────────────┬────────────┬────────────┬────────────┐
  │  Type      │  Length    │   NLPID    │  ...       │
  │            │            │            │            │
  └────────────┴────────────┴────────────┴────────────┘

*/

class tlv_129 {
    public:
	tlv_129() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(129);
		tlv_length(1);
		nlpid(0xcc);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void nlpid(unsigned char n) { rep_[2] = n; }

	friend std::istream& operator>>(std::istream& is, tlv_129& header) { return is.read(reinterpret_cast<char*>(header.rep_), 3); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_129& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 3);
	}

    private:
	unsigned char rep_[3];
};

/*


  0            8            16                       31
  ┌────────────┬────────────┬─────────────────────────┐
  │  Type      │  Length    │    Area Address         │
  │            │            │                         │
  ├────────────┴────────────┼─────────────────────────┘
  │   Area Address          │
  │                         │
  └─────────────────────────┘
*/

/*class tlv_1 {
    public:
	tlv_1() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(1);
		tlv_length(4);
		area(AREA);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void area(unsigned char* n) { std::memcpy(rep_ + 2, n, sizeof(AREA)); }

	friend std::istream& operator>>(std::istream& is, tlv_1& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_1& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};*/

/*

    0            8            16                       31
    ┌────────────┬────────────┬─────────────────────────┐
    │  Type      │  Length    │   IP address            │
    │            │            │                         │
    ├────────────┴────────────┼─────────────────────────┘
    │   IP address            │
    │                         │
    └─────────────────────────┘
*/

class tlv_132 {
    public:
	tlv_132() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(132);
		tlv_length(4);
		//ip_address(OUR_IP_ADDRESS);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void ip_address(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, tlv_132& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_132& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/*


 0            8            16                       31
 ┌─────────────────────────┬─────────────────────────┐
 │    PDU Length           │    Source-ID            │
 │                         │                         │
 ├─────────────────────────┴─────────────────────────┤
 │     Source-ID                                     │
 │                                                   │
 ├────────────┬────────────┬─────────────────────────┤      │
 │  Type      │  Length    │      LSP ID             │      │  LSP entries TLV9
 │            │            │                         │      │         x
 ├────────────┴────────────┴─────────────────────────┤      │  LSP entry
 │         LSP ID                                    │      │
 │                                                   │      │
 ├─────────────────────────┬─────────────────────────┤      │
 │   LSP ID                │   LSP sequence number   │      │
 │                         │                         │      │
 ├─────────────────────────┼─────────────────────────┤      │
 │  LSP sequence number    │  Remaining lifetime     │      │
 │                         │                         │      │
 ├─────────────────────────┼─────────────────────────┘      │
 │  Checksum               │
 │                         │
 └─────────────────────────┘
		      ...

 */

class isis_psnp_header {
    public:
	isis_psnp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	unsigned char* system_id() { return &rep_[2]; };
	unsigned short pdu_length() const { return decode(0, 1); };

	friend std::istream& operator>>(std::istream& is, isis_psnp_header& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 8);
	}

	friend std::ostream& operator<<(std::ostream& os, const isis_psnp_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 8);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[8];
};

/* tlv9  */
class tlv_9 {
    public:
	tlv_9() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(9);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }

	unsigned char tlv_length() const { return rep_[1]; };

	friend std::istream& operator>>(std::istream& is, tlv_9& header) { return is.read(reinterpret_cast<char*>(header.rep_), 2); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_9& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned char rep_[2];
};

/* lsp  entry, used with tlv9 */
class lsp_entry {
    public:
	lsp_entry() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	friend std::istream& operator>>(std::istream& is, lsp_entry& header) { return is.read(reinterpret_cast<char*>(header.rep_), 16); }

	friend std::ostream& operator<<(std::ostream& os, const lsp_entry& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 16);
	}

	unsigned char* lsp_id() { return &rep_[2]; };

    private:
	unsigned char rep_[16];
};

/*


   0            8            16                       31
   ┌─────────────────────────┬─────────────────────────┐
   │    PDU Length           │    Source-ID            │
   │                         │                         │
   ├─────────────────────────┴─────────────────────────┤
   │     Source-ID                                     │
   │                                                   │
   ├────────────┬──────────────────────────────────────┤
   │  Source-ID │   Start LSP-ID                       │
   │            │                                      │
   ├────────────┴──────────────────────────────────────┤
   │      Start LSP-ID                                 │
   │                                                   │
   ├────────────┬──────────────────────────────────────┤
   │Start LSP-ID│  End LSP-ID                          │
   │            │                                      │
   ├────────────┴──────────────────────────────────────┤
   │               End LSP-ID                          │
   │                                                   │
   ├────────────┬──────────────────────────────────────┘
   │ End LSP-ID │
   │            │
   └────────────┘

		...              x   LSP entries TLV9

 */

class isis_csnp_header {
    public:
	isis_csnp_header() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		//source_id(SOURCE_ID);
		start_lsp_id(START_LSP_ID);
		end_lsp_id(END_LSP_ID);
	}

	void pdu_length(unsigned short n) { encode(0, 1, n); }
	void source_id(unsigned char* n) { std::memcpy(&rep_[2], n, 7); }
	void start_lsp_id(unsigned char* n) { std::memcpy(&rep_[9], n, sizeof(START_LSP_ID)); }
	void end_lsp_id(unsigned char* n) { std::memcpy(&rep_[18], n, sizeof(END_LSP_ID)); }

	unsigned short pdu_length() const { return decode(0, 1); };

	friend std::istream& operator>>(std::istream& is, isis_csnp_header& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 25);
	}

	friend std::ostream& operator<<(std::ostream& os, const isis_csnp_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 25);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[25];
};

/*
class isis_csnp_1lsp {
    public:
	isis_csnp_1lsp() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(9);
		tlv_length(16);
		lsp_id(OUR_LSP_ID);
		lsp_seq(OUR_LSP_SEQ);
		lifetime(OUR_LSP_LT);
	}
	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void lifetime(unsigned char* n) { std::memcpy(&rep_[2], n, 2); }
	void lsp_id(unsigned char* n) { std::memcpy(&rep_[4], n, 8); }
	void lsp_seq(unsigned char* n) { std::memcpy(&rep_[12], n, 4); }
	void lsp_checksum(unsigned char* n) { std::memcpy(&rep_[16], n, 2); }

	friend std::istream& operator>>(std::istream& is, isis_csnp_1lsp& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 18);
	}

	friend std::ostream& operator<<(std::ostream& os, const isis_csnp_1lsp& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 18);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[18];
}; */

/*

     0            8            16                       31
     ┌─────────────────────────┬─────────────────────────┐
     │    PDU Length           │ Remaining-Lifetime      │
     │                         │                         │
     ├─────────────────────────┴─────────────────────────┤
     │     LSP ID                                        │
     │                                                   │
     ├───────────────────────────────────────────────────┤
     │     LSP ID                                        │
     │                                                   │
     ├─────────────────────────┬─────────────────────────┤
     │ Sequence Number         │  Checksum               │
     │                         │                         │
     ├────────────┬────────────┴─────────────────────────┘
     │ Type Block │
     │            │
     └────────────┘

		    ...   TLVs
*/

class isis_lsp_header {
    public:
	isis_lsp_header() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		type_block(0x3);
	}

	void pdu_length(unsigned short n) { encode(0, 1, n); }
	void remaining_lifetime(unsigned short n) { encode(2, 3, n); }
	void lsp_id(unsigned char* n) { std::memcpy(&rep_[4], n, sizeof(START_LSP_ID)); }
	void sequence_num(unsigned char* n) { std::memcpy(&rep_[12], n, 4); }
	void checksum(unsigned short n) { encode(16, 17, n); }
	void type_block(unsigned char n) { rep_[18] = n; }

	friend std::istream& operator>>(std::istream& is, isis_lsp_header& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 19);
	}

	friend std::ostream& operator<<(std::ostream& os, const isis_lsp_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 19);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[b] = static_cast<unsigned char>(n >> 8);
		rep_[a] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[19];
};

/* TLVs

  0            8            16                       31
  ┌────────────┬────────────┬──────────────────────────
  │  Type      │  Length    │    Value ...
  │            │            │
  └────────────┴────────────┴──────────────────────────


*/

class tlv_137 {
    public:
	tlv_137() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(137);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void tlv_hostname(unsigned char* n, std::size_t l) { std::memcpy(rep_ + 2, n, l); }

	unsigned char tlv_length() const { return rep_[1]; };
	unsigned char* data() { return &rep_[0]; };

	friend std::istream& operator>>(std::istream& is, tlv_137& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), header.rep_[1] + 2);
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv_137& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), header.rep_[1] + 2);
	}

    private:
	unsigned char rep_[257];
};

/* Originating buffer size  */

class tlv_14 {
    public:
	tlv_14() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(14);
		tlv_length(2);
	}
	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void set_size(unsigned short n) { encode(2, 3, n); }
	friend std::istream& operator>>(std::istream& is, tlv_14& header) { return is.read(reinterpret_cast<char*>(header.rep_), 4); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_14& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 4);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[b] = static_cast<unsigned char>(n >> 8);
		rep_[a] = static_cast<unsigned char>(n & 0xFF);
	}
	unsigned char rep_[4];
};

/* Protocols supported tlv129 > 1*/

class tlv_129_ext {
    public:
	tlv_129_ext() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(129);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void nlpid(unsigned char n, unsigned int index) {
		if (index <= 2) {
			rep_[index + 2] = n;
		};
	}

	friend std::istream& operator>>(std::istream& is, tlv_129_ext& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), header.rep_[1] + 2);
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv_129_ext& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), header.rep_[1] + 2);
	}

    private:
	unsigned char rep_[5];
};

/* Traffic Engineering Router ID tlv 134 */

class tlv_134 {
    public:
	tlv_134() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(134);
		tlv_length(4);
		//ip_address(OUR_IP_ADDRESS);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void ip_address(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, tlv_134& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_134& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* ipv6 interface address tlv 232 */

class tlv_232 {
    public:
	tlv_232() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(232);
		tlv_length(16);
		//ip_address(OUR_IPV6_ADDRESS);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void ip_address(unsigned char* n) { std::memcpy(rep_ + 2, n, 16); }

	friend std::istream& operator>>(std::istream& is, tlv_232& header) { return is.read(reinterpret_cast<char*>(header.rep_), 18); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_232& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 18);
	}

    private:
	unsigned char rep_[18];
};

/* Router capability  tlv 242 */
class tlv_242 {
    public:
	tlv_242() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(242);
		tlv_length(5);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void router_id(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }
	void flags(unsigned char n) { rep_[6] = n; }
	unsigned char get_length() { return rep_[1]; }

	friend std::istream& operator>>(std::istream& is, tlv_242& header) { return is.read(reinterpret_cast<char*>(header.rep_), 7); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_242& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 7);
	}

    private:
	unsigned char rep_[7];
};

/* subtlvs */
/* sr capability subtlv 2 */
class subtlv242_2 {
    public:
	subtlv242_2() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(2);
		tlv_length(9);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void flags(unsigned char n) { rep_[2] = n; }
	void range(unsigned char* n) { std::memcpy(rep_ + 3, n, 3); }
	void sid_label(unsigned char* n) { std::memcpy(rep_ + 6, n, 5); }   // it's subtlv type 1 length 3 

	friend std::istream& operator>>(std::istream& is, subtlv242_2& header) { return is.read(reinterpret_cast<char*>(header.rep_), 11); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv242_2& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 11);
	}

    private:
	unsigned char rep_[11];
};

/* sr algorithm subtlv 19 */

class subtlv242_19 {
    public:
	subtlv242_19() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(19);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }

	friend std::istream& operator>>(std::istream& is, subtlv242_19& header) { return is.read(reinterpret_cast<char*>(header.rep_), 2); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv242_19& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned char rep_[2];
};

class subtlv242_19_algo {
    public:
	subtlv242_19_algo() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	void algo(unsigned char n) { rep_[0] = n; }

	friend std::istream& operator>>(std::istream& is, subtlv242_19_algo& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 1);
	}

	friend std::ostream& operator<<(std::ostream& os, const subtlv242_19_algo& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 1);
	}

    private:
	unsigned char rep_[1];
};

/* sr node maximum sid dense 23 */

class subtlv242_23 {
    public:
	subtlv242_23() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(23);
		tlv_length(2);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void msd_type(unsigned char n) { rep_[2] = n; }
	void msd_value(unsigned char n) { rep_[3] = n; }

	friend std::istream& operator>>(std::istream& is, subtlv242_23& header) { return is.read(reinterpret_cast<char*>(header.rep_), 4); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv242_23& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 4);
	}

    private:
	unsigned char rep_[4];
};

/* Extended IP Reachability  tlv 135 */

class tlv_135 {
    public:
	tlv_135() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(135);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }

	friend std::istream& operator>>(std::istream& is, tlv_135& header) { return is.read(reinterpret_cast<char*>(header.rep_), 2); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_135& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned char rep_[2];
};

/* substructs and subtlvs */
/* substruct Ext. IP rechability */

class tlv135_ipreach {
    public:
	tlv135_ipreach() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	void metric(unsigned char* n) { std::memcpy(rep_, n, 4); }
	void flags(unsigned char n) { rep_[4] = n; }
	void ipv4_prefix(unsigned char* n) { std::memcpy(rep_ + 5, n, 4); }
	void sub_clv_length(unsigned char n) { rep_[9] = n; }
	void sub_clv_present() { rep_[4] |= (1 << 6); }
	unsigned char flags() const { return rep_[4]; };
	unsigned char stl() const { return rep_[9]; };
	unsigned int prefix_bytes(const unsigned char flags) const {
		if (((unsigned int)(flags & 0x3F) % 8) == 0) {
			return (unsigned int)(flags & 0x3F) / 8;
		} else {
			return (unsigned int)(flags & 0x3F) / 8 + 1;
		}
	}
	unsigned int stl_bytes() const {
		if (stl()) {
			return 1;
		} else {
			return 0;
		}
	}

	// on read here will be 5, need putback
	friend std::istream& operator>>(std::istream& is, tlv135_ipreach& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 5 + header.prefix_bytes(header.flags()) + header.stl_bytes());
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv135_ipreach& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 5 + header.prefix_bytes(header.flags()) + header.stl_bytes());
	}

    private:
	unsigned char rep_[10];
};

/* sr subtlv */

class prefix_sid {
    public:
	prefix_sid() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(3);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void flags(unsigned char n) { rep_[2] = n; }
	void algo(unsigned char n) { rep_[3] = n; }
	void offset(unsigned char* n) { std::memcpy(rep_ + 4, n, 4); }
	void label(unsigned char* n) { std::memcpy(rep_ + 4, n, 3); }
	unsigned char flags() const { return rep_[4]; };

	unsigned char get_length() const { return rep_[1]; }

	friend std::istream& operator>>(std::istream& is, prefix_sid& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 2 + static_cast<unsigned int>(header.get_length()));
	}

	friend std::ostream& operator<<(std::ostream& os, const prefix_sid& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2 + static_cast<unsigned int>(header.get_length()));
	}

    private:
	unsigned char rep_[8];
};

/* ipv6 reachability tlv 236 */

class tlv_236 {
    public:
	tlv_236() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(236);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }

	friend std::istream& operator>>(std::istream& is, tlv_236& header) { return is.read(reinterpret_cast<char*>(header.rep_), 2); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_236& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned char rep_[2];
};

class tlv236_ipv6reach {
    public:
	tlv236_ipv6reach() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	void metric(unsigned char* n) { std::memcpy(rep_, n, 4); }
	void flags(unsigned char n) { rep_[4] = n; }
	void ipv6_prefix(unsigned char* n) { std::memcpy(rep_ + 5, n, 16); }

	friend std::istream& operator>>(std::istream& is, tlv236_ipv6reach& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 21);
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv236_ipv6reach& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 21);
	}

    private:
	unsigned char rep_[21];
};

/* Extended IS reachability tlv 22 */
/*

  0            8            16                       31
  ┌────────────┬────────────┬──────────────────────────┐
  │  Type      │  Length    │  Neighbor Sys ID         │
  │            │            │                          │
  ├────────────┴────────────┴──────────────────────────┤
  │               Neighbor Sys ID                      │
  │                                                    │
  ├────────────┬───────────────────────────────────────┤
  │ Neighbor   │       Metric                          │
  │ Sys ID     │                                       │
  ├────────────┼───────────────────────────────────────┘
  │ SubCLV     │
  │ Length     │   ...
  └────────────┘

*/

class tlv_22 {
    public:
	tlv_22() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(22);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void neighbor_sysid(unsigned char* n) { std::memcpy(rep_ + 2, n, 7); }
	void metric(unsigned char* n) { std::memcpy(rep_ + 9, n, 3); }
	void subclv_length(unsigned char n) { rep_[12] = n; }

	friend std::istream& operator>>(std::istream& is, tlv_22& header) { return is.read(reinterpret_cast<char*>(header.rep_), 13); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_22& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 13);
	}

    private:
	unsigned char rep_[13];
};

/* subtlvs */
/* subtlv c6 ip addr */

class subtlv22_c6 {
    public:
	subtlv22_c6() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(6);
		subtlv_length(4);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void ip_address(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }
        unsigned char* ip_address() { return rep_ + 2; }

	friend std::istream& operator>>(std::istream& is, subtlv22_c6& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c6& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* subtlv c8 neighbor ip addr */

class subtlv22_c8 {
    public:
	subtlv22_c8() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(8);
		subtlv_length(4);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void ip_address(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c8& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c8& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* subtlv c4 neighbor ip link local/remote ids */

class subtlv22_c4 {
    public:
	subtlv22_c4() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(4);
		subtlv_length(8);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void link_local_id(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }
	void link_remote_id(unsigned char* n) { std::memcpy(rep_ + 6, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c4& header) { return is.read(reinterpret_cast<char*>(header.rep_), 10); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c4& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 10);
	}

    private:
	unsigned char rep_[10];
};

/* subtlv c11 unreserved bandwidth */

class subtlv22_c11 {
    public:
	subtlv22_c11() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(11);
		subtlv_length(32);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void priority_level(unsigned char* n, unsigned int index) { std::memcpy(rep_ + index * 4 + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c11& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 34);
	}

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c11& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 34);
	}

    private:
	unsigned char rep_[34];
};

/* subtlv c10 max reservable bandwidth */

class subtlv22_c10 {
    public:
	subtlv22_c10() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(10);
		subtlv_length(4);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void bandwidth(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c10& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c10& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* subtlv c9 max link bandwidth */

class subtlv22_c9 {
    public:
	subtlv22_c9() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(9);
		subtlv_length(4);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void bandwidth(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c9& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c9& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* subtlv c3 admin groups colors */

class subtlv22_c3 {
    public:
	subtlv22_c3() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(9);
		subtlv_length(4);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void groups(unsigned char* n) { std::memcpy(rep_ + 2, n, 4); }

	friend std::istream& operator>>(std::istream& is, subtlv22_c3& header) { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c3& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 6);
	}

    private:
	unsigned char rep_[6];
};

/* subtlv c31 adjacency sid */

class subtlv22_c31 {
    public:
	subtlv22_c31() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		subtlv_type(31);
	}

	void subtlv_type(unsigned char n) { rep_[0] = n; }
	void subtlv_length(unsigned char n) { rep_[1] = n; }
	void flags(unsigned char n) { rep_[2] = n; }
	void weight(unsigned char n) { rep_[3] = n; }
	void sid(unsigned char* n) { std::memcpy(rep_ + 4, n, 3); }
	void offset(unsigned char* n) { std::memcpy(rep_ + 4, n, 4); }

	unsigned char get_length() const { return rep_[1]; }
	unsigned char flags() const { return rep_[2]; }

	friend std::istream& operator>>(std::istream& is, subtlv22_c31& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 2 + static_cast<unsigned int>(header.get_length()));
	}

	friend std::ostream& operator<<(std::ostream& os, const subtlv22_c31& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2 + static_cast<unsigned int>(header.get_length()));
	}

    private:
	unsigned char rep_[8];
};

class tlv_1_ext {
    public:
	tlv_1_ext() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(1);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void area_length(unsigned char n) { rep_[2] = n; }
	void area(unsigned char* n, std::size_t l) { std::memcpy(rep_ + 3, n, l); }
        unsigned char* get_area() {  return rep_+3; };

	friend std::istream& operator>>(std::istream& is, tlv_1_ext& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), header.rep_[1] + 2);
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv_1_ext& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), header.rep_[1] + 2);
	}

    private:
	unsigned char rep_[16];
};

/* Multi topology tlv 229 */

class tlv_229 {
    public:
	tlv_229() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(229);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	friend std::istream& operator>>(std::istream& is, tlv_229& header) { return is.read(reinterpret_cast<char*>(header.rep_), 2); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_229& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned char rep_[2];
};

class tlv_229_topology {
    public:
	tlv_229_topology() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	void topology(unsigned short n) { encode(0, 1, n); }

	friend std::istream& operator>>(std::istream& is, tlv_229_topology& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 2);
	}

	friend std::ostream& operator<<(std::ostream& os, const tlv_229_topology& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 2);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[2];
};

/* MT IS tlv 222 */

class tlv_222 {
    public:
	tlv_222() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(222);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void topology_id(unsigned short n) { encode(2, 3, n); }
	void neighbor_sysid(unsigned char* n) { std::memcpy(rep_ + 4, n, 7); }
	void metric(unsigned char* n) { std::memcpy(rep_ + 11, n, 3); }
	void subclv_length(unsigned char n) { rep_[14] = n; }

	friend std::istream& operator>>(std::istream& is, tlv_222& header) { return is.read(reinterpret_cast<char*>(header.rep_), 15); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_222& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 15);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[15];
};

// ext IS tlv go

/* MT ipv4 tlv 235 */

class tlv_235 {
    public:
	tlv_235() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(235);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void topology_id(unsigned short n) { encode(2, 3, n); }

	friend std::istream& operator>>(std::istream& is, tlv_235& header) { return is.read(reinterpret_cast<char*>(header.rep_), 4); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_235& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 4);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[4];
};

// ext ip reach go

/* MT ipv6 tlv 237 */

class tlv_237 {
    public:
	tlv_237() {
		std::fill(rep_, rep_ + sizeof(rep_), 0);
		tlv_type(237);
	}

	void tlv_type(unsigned char n) { rep_[0] = n; }
	void tlv_length(unsigned char n) { rep_[1] = n; }
	void topology_id(unsigned short n) { encode(2, 3, n); }

	friend std::istream& operator>>(std::istream& is, tlv_237& header) { return is.read(reinterpret_cast<char*>(header.rep_), 4); }

	friend std::ostream& operator<<(std::ostream& os, const tlv_237& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 4);
	}

    private:
	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n) {
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[4];
};

// ipv6 reach go

