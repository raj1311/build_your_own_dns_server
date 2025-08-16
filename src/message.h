#pragma once

#include <array>
#include <cstdint>
#include <netinet/in.h>

namespace dns {

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

  std::array<uint16_t, 6> to_network_endianness() const {
    std::array<uint16_t, 6> response;
    response[0] = htons(packet_id);

    uint16_t flags = 0;
    flags |= query_response_indicator << 15;
    flags |= opcode << 11;
    flags |= authoritative_answer << 10;
    flags |= truncation << 9;
    flags |= recursion_desired << 8;
    flags |= recursion_available << 7;
    flags |= reserved << 4;
    flags |= response_code;
    response[1] = htons(flags);

    response[2] = htons(question_count);
    response[3] = htons(answer_record_count);
    response[4] = htons(authority_record_count);
    response[5] = htons(additional_record_count);

    return response;
  }
};    
struct Message {
    Header header;
  };

static_assert(sizeof(Message) == 12);
}