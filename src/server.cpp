#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "message.h"
#include "server.h"

int main() {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

      // Uncomment this block to pass the first stage
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

   int bytesRead;
   char buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);

   while (true) {
       // Receive data
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }

       buffer[bytesRead] = '\0';
       std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;


       // Create an empty response
    dns::Header default_header{
        .packet_id = 1234,
        .query_response_indicator = 1,
        .opcode = 0,
        .authoritative_answer = 0,
        .truncation = 0,
        .recursion_desired = 0,
        .recursion_available = 0,
        .reserved = 0,
        .response_code = 0,
        .question_count = 1,
        .answer_record_count = 0,
        .authority_record_count = 0,
        .additional_record_count = 0,
    };

    dns::Question default_question{
        .names = {"codecrafters","io"},
        .type = 1, // A record
        .class_ = 1 // IN class
    };

       // Create a response message

    dns::Message response_message;
       response_message.header = default_header;
       response_message.questions.push_back(default_question);

       // Create an empty response
        std::vector<uint8_t> response;
        serializePacket(response_message, response);

        // Send response
        if (sendto(udpSocket, response.data(), sizeof(response_message), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1)
        {
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
