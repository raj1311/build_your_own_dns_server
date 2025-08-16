#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include "message.h"
#include "server.h"

int main(int argc, char** argv) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

    // parse args: expect --resolver <ip:port>
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " --resolver <ip:port>" << std::endl;
        return 1;
    }
    std::string resolver_arg;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--resolver") {
            resolver_arg = argv[i + 1];
            break;
        }
    }
    if (resolver_arg.empty()) {
        std::cerr << "Missing --resolver argument" << std::endl;
        return 1;
    }
    auto pos = resolver_arg.find(':');
    if (pos == std::string::npos) {
        std::cerr << "Resolver address must be in ip:port format" << std::endl;
        return 1;
    }
    std::string resolver_ip = resolver_arg.substr(0, pos);
    int resolver_port = std::stoi(resolver_arg.substr(pos + 1));

      // create UDP socket to listen for tester requests
   int udpSocket;
   struct sockaddr_in clientAddress;

   udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
   if (udpSocket == -1) {
       std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
       return 1;
   }

   // Since the tester restarts your program quite often, setting REUSE_PORT
   // ensures that we don't run into 'Address already in use' errors
   int reuse = 1;
   if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
       std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
       return 1;
   }

   sockaddr_in serv_addr = { .sin_family = AF_INET,
                             .sin_port = htons(2053),
                             .sin_addr = { htonl(INADDR_ANY) },
                           };

   if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
       std::cerr << "Bind failed: " << strerror(errno) << std::endl;
       return 1;
   }

   // prepare resolver sockaddr
   sockaddr_in resolverAddr;
   std::memset(&resolverAddr, 0, sizeof(resolverAddr));
   resolverAddr.sin_family = AF_INET;
   resolverAddr.sin_port = htons(static_cast<uint16_t>(resolver_port));
   if (inet_pton(AF_INET, resolver_ip.c_str(), &resolverAddr.sin_addr) != 1) {
       std::cerr << "Invalid resolver IP: " << resolver_ip << std::endl;
       return 1;
   }

   // socket used for talking to resolver (ephemeral port)
   int resolverSock = socket(AF_INET, SOCK_DGRAM, 0);
   if (resolverSock == -1) {
       std::cerr << "Resolver socket creation failed: " << strerror(errno) << std::endl;
       return 1;
   }
   // set receive timeout so we don't block indefinitely waiting for resolver responses
   struct timeval tv;
   tv.tv_sec = 2;
   tv.tv_usec = 0;
   setsockopt(resolverSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

   int bytesRead;
   uint8_t buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);

   while (true) {
       // Receive data from tester
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }

       std::cout << "Received " << bytesRead << " bytes" << std::endl;

       // Parse the received data into a DNS message
       dns::Message message;
       if (!dns::Message::parse(reinterpret_cast<const uint8_t*>(buffer), static_cast<size_t>(bytesRead), message)) {
           std::cerr << "Failed to parse DNS message" << std::endl;
           continue; // Skip to next iteration
       }
       std::cout << "Parsed DNS message with " << message.questions.size() << " questions and "
                 << message.answers.size() << " answers." << std::endl;

       if (message.header.question_count == 0) {
           std::cerr << "No questions in the query; ignoring" << std::endl;
           continue;
       }

       // For each question we need to send a separate query to the resolver (per stage requirements)
       std::vector<dns::Answer> aggregated_answers;
       bool any_error = false;
       uint16_t combined_rcode = 0;
       uint16_t recursion_available_flag = 0;

       for (const auto& q : message.questions) {
           // Build a single-question packet to forward
           dns::Message forward_msg;
           forward_msg.header = message.header;
           forward_msg.header.question_count = 1;
           forward_msg.header.answer_record_count = 0;
           forward_msg.header.authority_record_count = 0;
           forward_msg.header.additional_record_count = 0;
           forward_msg.header.query_response_indicator = 0; // it's a query when sending to resolver
           forward_msg.questions.clear();
           forward_msg.questions.push_back(q);
           forward_msg.answers.clear();

           std::vector<uint8_t> forward_data = forward_msg.serialize();

           // send to resolver
           ssize_t sent = sendto(resolverSock, forward_data.data(), forward_data.size(), 0,
                                 reinterpret_cast<struct sockaddr*>(&resolverAddr), sizeof(resolverAddr));
           if (sent == -1) {
               std::cerr << "Failed to send to resolver: " << strerror(errno) << std::endl;
               any_error = true;
               break;
           }

           // wait for response from resolver
           uint8_t resp_buf[512];
           sockaddr_in fromAddr;
           socklen_t fromLen = sizeof(fromAddr);
           ssize_t resp_len = recvfrom(resolverSock, resp_buf, sizeof(resp_buf), 0, reinterpret_cast<struct sockaddr*>(&fromAddr), &fromLen);
           if (resp_len == -1) {
               std::cerr << "No response from resolver or recv error: " << strerror(errno) << std::endl;
               any_error = true;
               break;
           }

           // parse resolver response
           dns::Message resolver_response;
           if (!dns::Message::parse(resp_buf, static_cast<size_t>(resp_len), resolver_response)) {
               std::cerr << "Failed to parse resolver response" << std::endl;
               any_error = true;
               break;
           }

           // collect answers
           for (const auto& a : resolver_response.answers) aggregated_answers.push_back(a);

           // collect flags
           recursion_available_flag = recursion_available_flag || resolver_response.header.recursion_available;
           if (resolver_response.header.response_code != 0) combined_rcode = resolver_response.header.response_code;
       }

       // prepare final response back to tester
       dns::Message response_message;
       response_message.header = message.header; // start from original
      // mark as a response (QR = 1)
      response_message.header.query_response_indicator = 1;
       response_message.header.answer_record_count = static_cast<uint16_t>(aggregated_answers.size());
       response_message.answers = std::move(aggregated_answers);
       response_message.questions = message.questions; // Include questions in the response

       // set additional flags in the response header
       response_message.header.recursion_available = recursion_available_flag;
       response_message.header.response_code = combined_rcode;

       // Serialize the response message
       std::vector<uint8_t> response_data = response_message.serialize();

       // Print the serialized data for debugging
       std::cout << "Serialized response size: " << response_data.size() << " bytes" << std::endl;

       // Send response — send actual payload length and use clientAddrLen
       if (sendto(udpSocket,
                 response_data.data(),
                 response_data.size(),               // <-- use vector.size(), not sizeof(vector)
                 0,
                 reinterpret_cast<struct sockaddr*>(&clientAddress),
                 clientAddrLen) == -1) {
          perror("Failed to send response");
      }
   }

   close(udpSocket);

    return 0;
}

void serializePacket(dns::Message &response_message, std::vector<uint8_t> &response)
{
    response_message.header.serialize(response);
    for (dns::Question question : response_message.questions)
    {
        question.serialize(response);
    }
}
