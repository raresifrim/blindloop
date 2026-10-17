/** @file
 *****************************************************************************

 flight control variables

 *****************************************************************************/

#ifndef _FLIGHTCONTROL_VARIABLES_H
#define _FLIGHTCONTROL_VARIABLES_H

#include "libsnark/gadgetlib1/protoboard_structured.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"

using libsnark::pb_variable;
using libsnark::protoboard;
using libsnark::structured_protoboard;

template<typename FieldT>
struct ADIRUVals {
  	static const size_t NUM_VALS = 9;
    FieldT p;
    FieldT q;
    FieldT r;
    FieldT v;
    FieldT alpha;
    FieldT beta;
    FieldT n;
    FieldT theta;
    FieldT phi;

    ADIRUVals() = default;
    ADIRUVals(std::vector<FieldT> fields){
      	assert(fields.size() == NUM_VALS);
    	this->p = fields[0];
        this->q = fields[1];
       	this->r = fields[2];
        this->v = fields[3];
        this->alpha = fields[4];
        this->beta = fields[5];
        this->n = fields[6];
        this->theta = fields[7];
        this->phi = fields[8];
    }
};

template<typename FieldT>
struct ADIRUVars {
    pb_variable<FieldT> p;
    pb_variable<FieldT> q;
    pb_variable<FieldT> r;
    pb_variable<FieldT> v;
    pb_variable<FieldT> alpha;
    pb_variable<FieldT> beta;
    pb_variable<FieldT> n;
    pb_variable<FieldT> theta;
    pb_variable<FieldT> phi;

    void allocate(protoboard<FieldT> &pb, const std::string &annotation);
    void allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation);
    void assign(protoboard<FieldT> &pb, ADIRUVals<FieldT> &adiru);
};

template<typename FieldT>
struct PilotControlsVals {
    static const size_t NUM_VALS = 3;
    FieldT qc;
    FieldT pc;
    FieldT betac;

    PilotControlsVals() = default;
    PilotControlsVals(std::vector<FieldT> fields){
		assert(fields.size() == NUM_VALS);
        this->qc = fields[0];
        this->pc = fields[1];
        this->betac = fields[2];
    }
};


template<typename FieldT>
struct PilotControlsVars {
    pb_variable<FieldT> qc;
    pb_variable<FieldT> pc;
    pb_variable<FieldT> betac;

    void allocate(protoboard<FieldT> &pb, const std::string &annotation);
    void allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation);
	void assign(protoboard<FieldT> &pb, PilotControlsVals<FieldT> &controls);
};


template<typename FieldT>
struct CommandVals {
  	static const size_t NUM_VALS = 4;
    FieldT pitch_trim;
    FieldT elevator;
    FieldT aileron;
    FieldT rudder;

    CommandVals(std::vector<FieldT> fields){
		assert(fields.size() == NUM_VALS);
        this->pitch_trim = fields[0];
        this->elevator = fields[1];
        this->aileron = fields[2];
        this->rudder = fields[3];
    }
};

template<typename FieldT>
struct CommandVars {
    pb_variable<FieldT> pitch_trim;
    pb_variable<FieldT> elevator;
    pb_variable<FieldT> aileron;
    pb_variable<FieldT> rudder;

    void allocate(protoboard<FieldT> &pb, const std::string &annotation);
    void allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation);
};



#include "flightcontrol_variables.tcc"

#endif //_FLIGHTCONTROL_VARIABLES_H
