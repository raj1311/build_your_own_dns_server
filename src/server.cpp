#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
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

       // Safe null-termination (don't write past buffer)
       if (bytesRead >= static_cast<int>(sizeof(buffer))) {
           buffer[sizeof(buffer) - 1] = '\0';
       } else {
           buffer[bytesRead] = '\0';
       }
       std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;

         // Parse the received data into a DNS message
        dns::Message message;
         if (!dns::Message::parse(reinterpret_cast<const uint8_t*>(buffer), bytesRead, message)) {
              std::cerr << "Failed to parse DNS message" << std::endl;
              continue; // Skip to next iteration
            }
        std::cout << "Parsed DNS message with " << message.questions.size() << " questions and "
                    << message.answers.size() << " answers." << std::endl;




       // Create an empty response
    dns::Header default_header{
        .packet_id = message.header.packet_id,
        .query_response_indicator = 1,
        .opcode = message.header.opcode,
        .authoritative_answer = 0,
        .truncation = 0,
        .recursion_desired = message.header.recursion_desired,
        .recursion_available = 0,
        .reserved = 0,
        .response_code = static_cast<uint16_t>(message.header.opcode == 0 ? 0 : 4), // cast fixes narrowing
        .question_count = message.header.question_count,
        .answer_record_count = message.header.question_count,
        .authority_record_count = 0,
        .additional_record_count = 0,
    };

    // dns::Question default_question{
    //     .names = message.questions[0].names,
    //     .type = 1, // A record
    //     .class_ = 1 // IN class
    // };

    // Create a answer for each question
    // For simplicity, we will just return a dummy answer with a fixed IP address
    // In a real DNS server, you would look up the actual IP address for the domain
    // For now, we will just return a dummy answer with a fixed IP address

    // Define a dummy implementation of getAnswersForQuestions
        std::vector<dns::Answer> answers;
        for (const auto& question : message.questions) {
            dns::Answer answer{
                .names = question.names,
                .type = 1, // A record
                .class_ = 1, // IN class
                .time_to_live = 300, // Time to live
                .length = 4, // Length of the data
                .data = std::vector<uint8_t>{127, 0, 0, 1} // Example IP address
            };
            answers.push_back(answer);
        }

       // Create a response message

    dns::Message response_message;
       response_message.header = default_header;
       response_message.answers = answers; // Use the answers from the received message
       response_message.questions = message.questions; // Use the questions from the received message

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
