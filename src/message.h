#pragma once

#include <array>
#include <cstdint>
#include <netinet/in.h>
#include <vector>
#include <string>

namespace dns {

// small helpers for big-endian read/write
static inline void append_u16_be(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}
static inline bool read_u16_be(const uint8_t* buf, size_t len, size_t offset, uint16_t &out) {
  if (offset + 2 > len) return false;
  out = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
  return true;
}

struct Header {
  uint16_t packet_id;
  uint16_t query_response_indicator : 1;
  uint16_t opcode : 4;
  uint16_t authoritative_answer : 1;
  uint16_t truncation : 1;
  uint16_t recursion_desired : 1;
  uint16_t recursion_available : 1;
  uint16_t reserved : 3;
  uint16_t response_code : 4;
  uint16_t question_count;
  uint16_t answer_record_count;
  uint16_t authority_record_count;
  uint16_t additional_record_count;

  // serialize header into wire bytes (big-endian)
  void serialize(std::vector<uint8_t>& out) const {
    append_u16_be(out, packet_id);
    uint16_t flags = 0;
    flags |= (query_response_indicator & 0x1) << 15;
    flags |= (opcode & 0xF) << 11;
    flags |= (authoritative_answer & 0x1) << 10;
    flags |= (truncation & 0x1) << 9;
    flags |= (recursion_desired & 0x1) << 8;
    flags |= (recursion_available & 0x1) << 7;
    flags |= (reserved & 0x7) << 4;
    flags |= (response_code & 0xF);
    append_u16_be(out, flags);
    append_u16_be(out, question_count);
    append_u16_be(out, answer_record_count);
    append_u16_be(out, authority_record_count);
    append_u16_be(out, additional_record_count);
  }

  // parse header from buffer at offset 0; returns true on success
  static bool parse(const uint8_t* buf, size_t len, Header& h) {
    if (len < 12) return false;
    uint16_t v;
    // ID
    if (!read_u16_be(buf, len, 0, v)) return false;
    h.packet_id = v;
    // FLAGS
    if (!read_u16_be(buf, len, 2, v)) return false;
    h.query_response_indicator = (v >> 15) & 0x1;
    h.opcode = (v >> 11) & 0xF;
    h.authoritative_answer = (v >> 10) & 0x1;
    h.truncation = (v >> 9) & 0x1;
    h.recursion_desired = (v >> 8) & 0x1;
    h.recursion_available = (v >> 7) & 0x1;
    h.reserved = (v >> 4) & 0x7;
    h.response_code = v & 0xF;
    // counts
    if (!read_u16_be(buf, len, 4, h.question_count)) return false;
    if (!read_u16_be(buf, len, 6, h.answer_record_count)) return false;
    if (!read_u16_be(buf, len, 8, h.authority_record_count)) return false;
    if (!read_u16_be(buf, len, 10, h.additional_record_count)) return false;
    return true;
  }
};

struct Question {
    // Domain name as sequence of labels (e.g. {"www","example","com"})
    std::vector<std::string> names;
    uint16_t type;    // Type of query (e.g., 1 = A)
    uint16_t class_;  // Class of query (e.g., 1 = IN)

    // serialize question into wire bytes (labels, 0, type, class)
    void serialize(std::vector<uint8_t>& out) const {
      for (const auto& label : names) {
        if (label.size() > 63) {
          // label too long; truncate defensively
        }
        out.push_back(static_cast<uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
      }
      // terminating zero length label
      out.push_back(0);
      append_u16_be(out, type);
      append_u16_be(out, class_);
    }

    // parse question from buffer starting at offset; updates offset to after question; returns false on error
    static bool parse(const uint8_t* buf, size_t len, size_t& offset, Question& q) {
      q.names.clear();
      // read labels until zero octet
      while (offset < len) {
        uint8_t L = buf[offset++];
        if (L == 0) break; // end of name
        if (L & 0xC0) {
          // compression (pointer) not handled here — return false to keep parse simple for now
          return false;
        }
        if (offset + L > len) return false;
        q.names.emplace_back(reinterpret_cast<const char*>(buf + offset), L);
        offset += L;
      }
      // need at least 4 bytes for type and class
      if (offset + 4 > len) return false;
      uint16_t v;
      if (!read_u16_be(buf, len, offset, v)) return false;
      q.type = v;
      offset += 2;
      if (!read_u16_be(buf, len, offset, v)) return false;
      q.class_ = v;
      offset += 2;
      return true;
    }
};

struct Message {
    Header header;
    std::vector<Question> questions; // Questions in the message

    // serialize header + questions (header.question_count is set to questions.size())
    std::vector<uint8_t> serialize() {
      std::vector<uint8_t> out;
      header.question_count = static_cast<uint16_t>(questions.size());
      header.serialize(out);
      for (const auto& q : questions) q.serialize(out);
      return out;
    }

    // parse entire message from buffer; returns true on success
    static bool parse(const uint8_t* buf, size_t len, Message& m) {
      if (!Header::parse(buf, len, m.header)) return false;
      size_t offset = 12;
      m.questions.clear();
      for (uint16_t i = 0; i < m.header.question_count; ++i) {
        Question q;
        if (!Question::parse(buf, len, offset, q)) return false;
        m.questions.push_back(std::move(q));
      }
      // additional sections (answers/authority/additional) omitted for brevity
      return true;
    }
};

} // namespace dns