//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef INET_NETWORKLAYER_IPV4_RL_SARSA_H_
#define INET_NETWORKLAYER_IPV4_RL_SARSA_H_

#include "inet/common/INETDefs.h"
#include <fstream>
#include <iostream>

#define MAX_Q_LENGTH 	    11
#define NUM_OF_ACTIONS 	    3
#define NUM_OF_BW 		    700
#define NUM_OF_Q_DELAY 	    500
#define NUM_OF_DROPS 	    15
#define PROB_FOR_EPSILON    1
//#define Q_FILE_NAME         "q_vals.bin"
//#define REWARD_FILE_NAME    "rewards.txt"
//#define CONST_ECN_THRSH     1

//#define NUM_OF_STATES NUM_OF_BW NUM_OF_Q_DELAY NUM_OF_DROPS NUM_OF_ACTIONS



namespace inet {

enum actions {
	nothing = 0,
	markEcn,
	drop
};



class INET_API RL_Sarsa : public cSimpleModule
{


public:
	RL_Sarsa();
	virtual ~RL_Sarsa();
	virtual void initialize() override;
	virtual void finish() override;

	void udpateQ(double r, uint32_t next_bw, uint32_t next_length, uint32_t next_drops, actions next_action);

	actions chooseAction(uint32_t bw, uint32_t qLength, uint32_t drops);

protected:

	std::array<std::array<std::array<std::array<double, NUM_OF_ACTIONS>, NUM_OF_DROPS>, MAX_Q_LENGTH>, NUM_OF_BW> q_func;
	int q_acc[MAX_Q_LENGTH][NUM_OF_ACTIONS] = {0};
	std::fstream q_file;

	void writeToTextFile(std::string fileName, long double value);


	bool testRun;
	bool guiRun;
	double rl_gamma {0};
	double rl_alpha {0};
	int epsilon {0};
	bool explorationFlag {true};
	long double realReward {0};
	long int realBw {0};
	long int realDrops {0};
	long int realTime {0};

	simtime_t observationLearnTime {0};
	std::string binQFileName;
	std::string txtQFileName;
	std::string rewardFileName;
	std::string bwFileName;
	std::string dropsFileName;
	std::string timeFileName;

	int current_bw 		{0};
	int current_drops 	{0};
	int current_qLength	{0};
	actions current_action {actions::nothing};



	//cLongHistogram hopCountStats;
	cOutVector *stateVec;

};

} /* namespace inet */

#endif /* INET_NETWORKLAYER_IPV4_RL_SARSA_H_ */
