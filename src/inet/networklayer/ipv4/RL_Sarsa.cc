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

#include "RL_Sarsa.h"
#include <algorithm>


using namespace std;

namespace inet {

Define_Module(RL_Sarsa);

RL_Sarsa::RL_Sarsa() {}

RL_Sarsa::~RL_Sarsa() {
	delete stateVec;
}

void RL_Sarsa::finish() {
	// Binary Q file
    if (!binQFileName.empty() && !testRun) {
        q_file = std::fstream(binQFileName, std::ios::out | std::ios::binary);
        if (q_file.is_open())
        {

            q_file.write((char*)&q_func[0], sizeof(q_func));
            q_file.close();
        }
    }
    if ((epsilon > 300 || epsilon ==0)  && !binQFileName.empty() && !testRun) {
        q_file = std::fstream(("q_vals_"+ std::to_string(epsilon) + ".bin"), std::ios::out | std::ios::binary);
        if (q_file.is_open())
        {

            q_file.write((char*)&q_func[0], sizeof(q_func));
            q_file.close();
        }
    }

    // Textual Q file
    if ((epsilon > 300 || epsilon ==0)  && !txtQFileName.empty() && !testRun) {
        std::fstream txt_q_file = std::fstream(("q_vals_"+ std::to_string(epsilon) + ".txt"), std::ios::out);
        if (txt_q_file.is_open())
        {


            for (auto &it_bw : q_func) {
                for (auto &it_qLength : it_bw) {
                    for (auto &it_drops : it_qLength) {
                        for (auto &it_actions : it_drops) {
                            txt_q_file << it_actions << "\t";
                        }
                    }
                }
                txt_q_file << std::endl;
            }

            txt_q_file.close();
        }
    }

    // Appending current accumulated reward to Reward file
    writeToTextFile(rewardFileName, realReward);
    writeToTextFile(bwFileName, realBw);
    writeToTextFile(dropsFileName, realDrops);
    writeToTextFile(timeFileName, realTime);


}


void RL_Sarsa::writeToTextFile(std::string fileName, long double value) {

    if (!fileName.empty()) {
        std::fstream wfile = std::fstream(fileName, std::ios::out  | std::ios::app);
        if (wfile.is_open())
        {
            if (testRun)
            {
                wfile << value << "\t" << getEnvir()->getConfigEx()->getVariable("repetition") << "\n";
            } else
            {
                wfile << value << "\t" << epsilon << "\n";
            }
            wfile.close();
        }
    }

}

void RL_Sarsa::initialize() {
	stateVec = new cOutVector("rlZeroStateVec");

    rl_gamma = par("learningGamma");
    rl_alpha = par("learningRate");
	//epsilon = PROB_FOR_EPSILON;
	epsilon = par("epsilon");
	observationLearnTime = par("observationLearnTime");
	explorationFlag = true;
	WATCH(explorationFlag);
	WATCH(epsilon);
	binQFileName = par("binQFileName").stdstringValue();
    txtQFileName = par("txtQFileName").stdstringValue();
	rewardFileName = par("rFileName").stdstringValue();
	bwFileName = par("bwFileName").stdstringValue();
	dropsFileName = par("dropsFileName").stdstringValue();
	timeFileName = par("timeFileName").stdstringValue();
	testRun = par("testRun");
	guiRun = par("guiRun");


	if (!binQFileName.empty())
	{
        struct stat buffer;
        auto fileExists = stat (binQFileName.c_str(), &buffer) == 0;

        if (fileExists)
        {
            q_file = std::fstream(binQFileName, std::ios::in | std::ios::binary);
            if (q_file.is_open())
            {
                q_file.seekg (0, std::ios::end);
                int qFileSize = q_file.tellg();
                q_file.seekg (0, std::ios::beg);

                if (qFileSize > 0)
                {
                    if (qFileSize == sizeof(q_func))
                    {
                        q_file.read((char*)&q_func[0], sizeof(q_func));
                    }
                }
                q_file.close();
                if (!testRun) {
                    std::remove(binQFileName.c_str()); // delete file
                }
                EV_DETAIL << "detail: RL Bin file loaded " << endl;
                EV_INFO << "info: RL Bin file loaded " << endl;

            }
        }
        // else if (testRun && ecn) {
        //    EV_ERROR << "This is test run with missing Q values file. Must have Q values...\n";
        //    throw cRuntimeError("Test run with missing %s file", binQFileName);
        // }
	}

	if (!txtQFileName.empty() && !testRun) {
        std::remove(txtQFileName.c_str()); // delete file
    }
	if (!bwFileName.empty() && !testRun) {
	    std::remove(bwFileName.c_str()); // delete file
    }
	if (!dropsFileName.empty() && !testRun) {
	    std::remove(dropsFileName.c_str()); // delete file
	}
	if (!timeFileName.empty() && !testRun) {
	    std::remove(timeFileName.c_str()); // delete file
	}

}

void RL_Sarsa::udpateQ(double r, uint32_t next_bw, uint32_t next_qLength, uint32_t next_drops, actions next_action)
{

    realReward += r;
    realBw += next_bw;
    //realBw = next_bw;
    realDrops += next_drops;
    realTime += 1;

    if (testRun) {
        return;
    }

    // Quantization
    next_bw = next_bw/100;

    // Boundary check
	next_bw 	= (next_bw >= NUM_OF_BW)?(NUM_OF_BW-1):next_bw;
	next_qLength 	= (next_qLength >= MAX_Q_LENGTH)?(MAX_Q_LENGTH-1):next_qLength;
	next_drops 	= (next_drops >= NUM_OF_DROPS)?(NUM_OF_DROPS-1):next_drops;

	q_acc[current_qLength][current_action] += 1;

	// Update Q-function
	q_func[current_bw][current_qLength][current_drops][current_action] =
			q_func[current_bw][current_qLength][current_drops][current_action] +
			rl_alpha * (
					r + rl_gamma * q_func[next_bw][next_qLength][next_drops][next_action] - q_func[current_bw][current_qLength][current_drops][current_action]
			);

	// Update current state
	current_bw 		= next_bw ;
	current_drops 	= next_drops;
	current_action 	= next_action;
	current_qLength	= next_qLength;


}

actions RL_Sarsa::chooseAction(uint32_t bw, uint32_t qLength, uint32_t drops)
{
    // Boundary check
	bw 		= (bw >= NUM_OF_BW)?(NUM_OF_BW-1):bw;
	qLength 	= (qLength >= MAX_Q_LENGTH)?(MAX_Q_LENGTH-1):qLength;
	drops 	= (drops >= NUM_OF_DROPS)?(NUM_OF_DROPS-1):drops;

	// Use RL after 1 sec
	simtime_t sim_now = simTime();
	//simtime_t sim_sec;
	//sim_sec.setRaw(1e12);
	//auto a = observationLearnTime;
	if (sim_now <= observationLearnTime) // 1sec
	{
	    return actions::nothing;
	}

	// Decying epsilon in continuous learning
	if (guiRun) {
	    int sum = 0;
        for (int i = 1; i < MAX_Q_LENGTH; ++i) {
            for (int j = 0; j < 3; ++j) {
                sum = sum + q_acc[i][j];
            }
        }
        epsilon = 1 + sum/1000;
    }

	if (!testRun && epsilon > 0)
	{
        int rNumr = rand();
        double P = (double)rNumr / (double)RAND_MAX;

        if ( P <= 1.0/(double)epsilon )
        {
            EV_INFO << "Random = " << rNumr % 3 << "<--------------------------------------------------\n\n\n\n\n\n\n\n";
            return actions(rNumr % 3);
        }

	}



	double doNothing 	= q_func[bw][qLength][drops][(int)actions::nothing];
	double doEcn 		= q_func[bw][qLength][drops][(int)actions::markEcn];
	double doDrop 		= q_func[bw][qLength][drops][(int)actions::drop];

	if ( (doNothing >= doEcn) && (doNothing >= doDrop) )
	{
		return actions::nothing;
	}

	if ( (doEcn >= doNothing) && (doEcn >= doDrop) )
	{
		return actions::markEcn;
	}
	EV_INFO << "doNothing = " << doNothing << " doEcn = " << doEcn <<" doDrop = " << doDrop <<"<--------------------------------------------------\n\n\n\n\n\n\n\n";
	return actions::drop;
}

} /* namespace inet */
