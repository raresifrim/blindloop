/** @file
*****************************************************************************

Networking for Demo Scenarios / Simulation

Provides classes for parties in a network, with routines for communication.
Communication is point to point, network participants are identified and
addressed by their name. Communication is either done directly in RAM using
a std::map, or via file-system. The latter option allows to demonstrate
correct serialization and deserialization.
*****************************************************************************/

#ifndef SCENARIO_NETWORK_H
#define SCENARIO_NETWORK_H

#include <string>
#include <iostream>
#include <streambuf>
#include <fstream>
#include <map>
#include <vector>
#include <stdexcept>
#include <boost/any.hpp>

class Communicator {
private:
    std::map<std::string, boost::any> map;
    uint16_t time;

public:
    enum CommunicationMode {File, Ram};

    CommunicationMode mode;

    Communicator(CommunicationMode mode=File)
    :  time(0), mode(mode) {}

    uint16_t get_time(){
        return time;
    }

    void tick(){
        time++;
    }

    template<typename T>
    void send_to(const T &content, const std::string &topic, const std::string &from, const std::string &to, bool binary=false){
        std::string handle = topic + "_" + from + "_" + to + "_T" + std::to_string(get_time());
        if (mode == File){
            std::ofstream output_file;
            if (binary) {
                output_file.open(handle, std::ios::out | std::ios::binary);
            }else{
                output_file.open(handle, std::ios::out);
            }
            output_file << content;
            output_file.close();
        }else if(mode == Ram){
            map[handle] = content;
        }else {
            throw std::runtime_error("Not implemented");
        }
    }

    template<typename T>
    T receive_from(const std::string &topic, const std::string &from, const std::string &to, bool binary=false){
        T content;
        std::string handle = topic + "_" + from + "_" + to + "_T" + std::to_string(get_time());
        if (mode == File){
            std::ifstream input_file;
            if (binary) {
                input_file.open(handle, std::ios::in | std::ios::binary);
            }else{
                input_file.open(handle, std::ios::in);
            }

            if (binary) {
                input_file >> std::noskipws >> content;
            }else{
                input_file >> content;
            }

            input_file.close();
        } else if(mode == Ram){
            content = boost::any_cast<T>(map[handle]);
        } else{
            throw std::runtime_error("Not implemented");
        }
        return content;
    }

};

extern Communicator default_comm;

class NetworkParticipant {
private:
    Communicator &comm;
protected:
    bool silent;

    uint16_t get_time(){
        return comm.get_time();
    }

    template<typename T>
    void send_to(const T &content, const std::string &topic, const std::string &to, bool binary=false) {
        comm.send_to<T>(content, topic, name, to, binary);
    }

    template<typename T>
    T receive_from(const std::string &topic, const std::string &from, bool binary=false) {
        return comm.receive_from<T>(topic, from, name, binary);
    }

public:
    std::string name;
    NetworkParticipant(std::string name, Communicator &comm, bool silent=false) : comm(comm), silent(silent), name(name)  {}
};



#endif //SCENARIO_NETWORK_H
