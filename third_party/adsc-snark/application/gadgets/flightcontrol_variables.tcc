/** @file
 *****************************************************************************

 See flightcontrol_variables.hpp

 *****************************************************************************/

#include "flightcontrol_variables.hpp"

template<typename FieldT>
void ADIRUVars<FieldT>::allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation)

{
    p.allocate_from_block(pb, block_id, FMT(annotation, ".p"));
    q.allocate_from_block(pb, block_id, FMT(annotation, ".q"));
    r.allocate_from_block(pb, block_id, FMT(annotation, ".r"));
    v.allocate_from_block(pb, block_id, FMT(annotation, ".v"));
    alpha.allocate_from_block(pb, block_id, FMT(annotation, ".alpha"));
    beta.allocate_from_block(pb, block_id, FMT(annotation, ".beta"));
    n.allocate_from_block(pb, block_id, FMT(annotation, ".n"));
    theta.allocate_from_block(pb, block_id, FMT(annotation, ".theta"));
    phi.allocate_from_block(pb, block_id, FMT(annotation, ".phi"));
}

template<typename FieldT>
void ADIRUVars<FieldT>::allocate(protoboard<FieldT> &pb, const std::string &annotation)

{
    p.allocate(pb, FMT(annotation, ".p"));
    q.allocate(pb, FMT(annotation, ".q"));
    r.allocate(pb, FMT(annotation, ".r"));
    v.allocate(pb, FMT(annotation, ".v"));
    alpha.allocate(pb, FMT(annotation, ".alpha"));
    beta.allocate(pb, FMT(annotation, ".beta"));
    n.allocate(pb, FMT(annotation, ".n"));
    theta.allocate(pb, FMT(annotation, ".theta"));
    phi.allocate(pb, FMT(annotation, ".phi"));
}

template<typename FieldT>
void ADIRUVars<FieldT>::assign(protoboard<FieldT> &pb, ADIRUVals<FieldT> &adiru)
{
    pb.val(this->p) = adiru.p;
    pb.val(this->q) = adiru.q;
    pb.val(this->r) = adiru.r;
    pb.val(this->v) = adiru.v;
    pb.val(this->alpha) = adiru.alpha;
    pb.val(this->beta) = adiru.beta;
    pb.val(this->n) = adiru.n;
    pb.val(this->theta) = adiru.theta;
    pb.val(this->phi) = adiru.phi;
}

template<typename FieldT>
void PilotControlsVars<FieldT>::allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation)
{
    qc.allocate_from_block(pb, block_id, FMT(annotation, ".qc"));
    pc.allocate_from_block(pb, block_id, FMT(annotation, ".pc"));
    betac.allocate_from_block(pb, block_id, FMT(annotation, ".betac"));
}

template<typename FieldT>
void PilotControlsVars<FieldT>::allocate(protoboard<FieldT> &pb, const std::string &annotation)
{
    qc.allocate(pb, FMT(annotation, ".qc"));
    pc.allocate(pb, FMT(annotation, ".pc"));
    betac.allocate(pb, FMT(annotation, ".betac"));
}

template<typename FieldT>
void PilotControlsVars<FieldT>::assign(protoboard<FieldT> &pb, PilotControlsVals<FieldT> &controls)
{
    pb.val(this->qc) = controls.qc;
    pb.val(this->pc) = controls.pc;
    pb.val(this->betac) = controls.betac;
}

template<typename FieldT>
void CommandVars<FieldT>::allocate_from_block(structured_protoboard<FieldT> &pb, size_t block_id, const std::string &annotation)
{
    pitch_trim.allocate_from_block(pb, block_id, FMT(annotation, ".qc"));
    elevator.allocate_from_block(pb, block_id, FMT(annotation, ".elevator"));
    aileron.allocate_from_block(pb, block_id, FMT(annotation, ".aileron"));
    rudder.allocate_from_block(pb, block_id, FMT(annotation, ".rudder"));
}

template<typename FieldT>
void CommandVars<FieldT>::allocate(protoboard<FieldT> &pb, const std::string &annotation)
{
    pitch_trim.allocate(pb, FMT(annotation, ".qc"));
    elevator.allocate(pb, FMT(annotation, ".elevator"));
    aileron.allocate(pb, FMT(annotation, ".aileron"));
    rudder.allocate(pb, FMT(annotation, ".rudder"));
}