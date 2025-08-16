#pragma once

#include <array>
#include <cstdint>
#include <netinet/in.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>

namespace dns {

// small helpers for big-endian read/write
static inline void append_u16_be(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}
static inline void append_u32_be(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}
static inline bool read_u16_be(const uint8_t* buf, size_t len, size_t offset, uint16_t &out) {
  if (offset + 2 > len) return false;
  out = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
  return true;
}
static inline bool read_u32_be(const uint8_t* buf, size_t len, size_t offset, uint32_t &out) {
  if (offset + 4 > len) return false;
  out = (static_cast<uint32_t>(buf[offset]) << 24) |
        (static_cast<uint32_t>(buf[offset + 1]) << 16) |
        (static_cast<uint32_t>(buf[offset + 2]) << 8) |
        (static_cast<uint32_t>(buf[offset + 3]));
  return true;
}

// parse domain name with compression support
static bool parse_name(const uint8_t* buf, size_t len, size_t &offset, std::vector<std::string> &labels) {
  labels.clear();
  size_t pos = offset;
  bool jumped = false;
  size_t max_depth = 128;
  size_t depth = 0;

  while (pos < len && depth++ < max_depth) {
    uint8_t L = buf[pos];
    if (L == 0) {
      // end of name
      if (!jumped) offset = pos + 1;
      return true;
    }
    if ((L & 0xC0) == 0xC0) {
      // pointer
      if (pos + 1 >= len) return false;
      uint16_t b1 = buf[pos] & 0x3F;
      uint16_t b2 = buf[pos + 1];
      uint16_t pointer = (b1 << 8) | b2;
      if (pointer >= len) return false;
      if (!jumped) offset = pos + 2; // advance original offset past the pointer
      pos = pointer;
      jumped = true;
      continue;
    }
    // label
    if (pos + 1 + L > len) return false;
    labels.emplace_back(reinterpret_cast<const char*>(buf + pos + 1), L);
    pos += 1 + L;
  }
  return false; // too deep or out of bounds
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
      if (!parse_name(buf, len, offset, q.names)) return false;
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

struct Answer{
  std::vector<std::string> names;
  uint16_t type;
  uint16_t class_;
  uint32_t time_to_live;
  uint16_t length;
  std::vector<uint8_t> data;

  // serialize answer into wire bytes (name, type, class, ttl, length, data)
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
      append_u32_be(out, time_to_live); // use 4 bytes for TTL
      append_u16_be(out, length);
      // copy data bytes
      out.insert(out.end(), data.begin(), data.end());
    }

    // parse answer from buffer starting at offset; updates offset to after answer; returns false on error
    static bool parse(const uint8_t* buf, size_t len, size_t& offset, Answer& a) {
      if (!parse_name(buf, len, offset, a.names)) return false;
      // need at least 10 bytes for type(2), class(2), ttl(4), length(2)
      if (offset + 10 > len) return false;
      uint16_t v16;
      uint32_t v32;
      if (!read_u16_be(buf, len, offset, v16)) return false;
      a.type = v16;
      offset += 2;
      if (!read_u16_be(buf, len, offset, v16)) return false;
      a.class_ = v16;
      offset += 2;
      if (!read_u32_be(buf, len, offset, v32)) return false;
      a.time_to_live = v32;
      offset += 4;
      if (!read_u16_be(buf, len, offset, v16)) return false;
      a.length = v16;
      offset += 2;
      if (offset + a.length > len) return false;
      a.data.resize(a.length);
      std::memcpy(a.data.data(), buf + offset, a.length);
      offset += a.length;
      return true;
    }

};

struct Message {
    Header header;
    std::vector<Question> questions; // Questions in the message
    std::vector<Answer> answers;     // Answers in the message

    // serialize header + questions + answers (header counts set automatically)
    std::vector<uint8_t> serialize() {
      std::vector<uint8_t> out;
      header.question_count = static_cast<uint16_t>(questions.size());
      header.answer_record_count = static_cast<uint16_t>(answers.size());
      header.serialize(out);
      for (const auto& q : questions) q.serialize(out);
      for (const auto& a : answers) a.serialize(out);
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
      m.answers.clear();
      for (uint16_t i = 0; i < m.header.answer_record_count; ++i) {
        Answer a;
        if (!Answer::parse(buf, len, offset, a)) return false;
        m.answers.push_back(std::move(a));
      }
      // authority/additional parsing can be added similarly
      return true;
    }
};

} // namespace dns