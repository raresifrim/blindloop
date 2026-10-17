% Check discretization of controller

Kp = 3;
Ki = 1.2;
Kd = 0.13;
Tf = 0.153;
Ts = 1/50;

pid_matlab = pid(Kp, Ki, Kd, Tf, Ts, 'IFormula', 'ForwardEuler', 'DFormula', 'ForwardEuler');
pid_matlab_tf = tf(pid_matlab);


a0 = 1;
a1 = Ts/Tf - 2;
a2 = 1 - Ts/Tf;
b0 = Kp+Kd/Tf;
b1 = Kp*(Ts/Tf-2) + Ki*Ts - 2*Kd/Tf;
b2 = Kp*(1 - Ts/Tf) + Ki*Ts*(Ts/Tf - 1) + Kd/Tf;

pid_tf = tf([b0, b1, b2], [a0, a1, a2], Ts);

A = [0, 1;  
    -a2, -a1];

B = [0; 
    1];

C = [b2-a2*b0, b1-a1*b0];
    
D = [b0];
pid_ss = ss(A, B, C, D, Ts);

bodeplot(pid_matlab, pid_tf, pid_ss);
legend('pid-matlab', 'pid-tf', 'pid-ss');