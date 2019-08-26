Emulation
=========

In INET, emulation is used in a broad sense to describe a system which
is partially implemented in the real world and partially in the simulation.
Emulation is often used for testing and validating a simulation model with
its real-world counterparts. It may also be used out of necessity, because
some part of the system only exists in the real world or as a simulation
model.

Developing using simulation is often cheaper, more practical and safer
than directly running experiments in the real world. However, a model
that succeeds in simulation does not necessarily work when deployed in
the real world.

After a simulation succeeds, it is a time consuming work to rewrite the
code and install it onto the appropriate devices to be able to actually
test it outside the simulation environment. Even if it is done, the
probability still stands that it will fail. Often there are
discrepancies between simulation and the real world, which results in
models that work well in simulation yet perform poorly in the real
world.

There are modules presented by INET that act as bridges between the
simulated and real domains, therefore it is possible to leave one part
of the simulation unchanged, while simply extracting the other into the
real world. Several setups are possible when one can take advantage of the emulation
capabilities of INET:

- simulated node in a real network
- a simulated subnet in real network
- real-world node in simulated network
- simulated protocol in a real network node
- real application in a simulated network node
- etc.

To act as a network emulator, two major problems need to be solved. On
one hand, the simulation must run in real time, or the real clock must be
configured according to the simulation time (synchronization). On the
other hand the simulation must be able to communicate with the real
world (communication). This is achieved in INET as the following:

- Synchronization:

  - ``RealTimeScheduler:`` It is a socket-aware real-time
    scheduler class responsible for synchronization. Using this method, the
    simulation is run according to real time.

  - (``OppClock``: A hypothetical method; the clocks of real applications running on the host OS are synchronized to the clock of the simulation. Note that this is just an idea; it's not available yet.)

- Communication:

   -  The interface between the real (an interface of the OS) and the
      simulated parts of the model are represented by `Ext` modules,
      with names beginning with ``Ext~`` prefix in the
      simulation (``ExtLowerUdp``, ``ExtUpperEthernetInterface``,
      etc.).

      Ext modules communicate both internally in the simulation and externally in the host OS.
      Packets sent to these modules in the simulation will be sent out on the host
      OS interface, and packets received by the host OS interface (or
      rather, the appropriate subset of them) will appear in the
      simulation as if received on an ``Ext~`` module.


      There are several possible ways to maintain the external communication:

      -  File
      -  Pipe
      -  Socket
      -  Shared memory
      -  TUN/TAP interfaces
      -  Message Passing Interface (MPI)

In order to run any emulation example, INET must be compiled with the
"Network Emulation" feature enabled. Enabling this feature can be done
by checking the
:menuselection:`IDE-->Project-->Properties-->OMNeT++/Project Features-->Network Emulation`
options.

In order to be able to send packets through raw sockets
applications require special permissions. There
are two ways to achieve this under linux.

The suggested solution is to use setcap to set the application
permissions:

.. code::

   $ sudo setcap cap_net_raw,cap_net_admin=eip /*fullpath*/opp_run
   $ sudo setcap cap_net_raw,cap_net_admin=eip /*fullpath*/opp_run_dbg
   $ sudo setcap cap_net_raw,cap_net_admin=eip /*fullpath*/opp_run_release

This solution makes running the examples from the IDE possible.
Alternatively, the application can be started with root privileges from
command line:


.. code::

   $ sudo `inet_dbg -p -u Cmdenv`

.. note:: In any case, it's generally a bad idea to start the IDE as superuser.
          Doing so may silently change the file ownership for certain IDE
          configuration files, and it may prevent the IDE to start up for the
          normal user afterwards.

The following showcases demonstrate several such emulation examples:

.. toctree::
   :maxdepth: 1

   babel/doc/index
