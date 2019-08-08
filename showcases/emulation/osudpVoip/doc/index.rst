Simulating VoIP Applications over the Real Network
==================================================

Goals
-----

TODO: what is the goal of THIS showcase really?
TODO: sounds bad
Voice over IP (VoIP) was developed in order to provide access to voice
communication in any place around the world. Media streams are
transported using special media delivery protocols that encode audio.

.. INET can be used to test how a real network affects VoIP traffic.

INET can be used to test a real network with realistic, simulated VoIP traffic.
One can examine how the quality of real audio is affected as it traverses the network.

This showcase demonstrates

  want to say:

  - INET is used to emulate VoIP traffic
  - There are modules that do that realistically, that is they take a sound file, encode it, fragment it, and send it via UDP. On the other side, the sound file is reconstructed, while simulating VoIP effects, such as de-jitter buffering and discarding timed-out packets
  - This showcase demonstrates this; the UDP packets are sent via the real network stack of the host OS
  - The simulated sender and receiver could run on different machines, while the traffic is sent via the real network
  - There are actually two emulation features here; VoIP encoding and traffic emulation, and UDP emulation

  why is it good?

  - you can hear how the transmission affects the audio (thats why the voip is good)
  - you can test a real network with voip traffic
  - what effect a real network has on voip traffic
  - test voip traffic in real (or simulated) network conditions and how it affects the audio
  - so to sum it up, INET can emulate VoIP traffic and send it through a real network (?)

what are we emulating?
in the network part, emulating the udp
in the voip part, emulating the a voip protocol...that is, from the point of view of the real world, it could be a real voip protocol. the packets are similar
so we're emulating voip traffic
and udp traffic?

TODO: is this needed?
INET framework features
various modules for emulating different models and scenarios, including
VoIP traffic.

This showcase demonstrates how one can run simulated VoIP applications
over a real network using INET components.

| INET version: ``4.0``
| Source files location: `inet/showcases/emulation/ExtUdpVoip <https://github.com/inet-framework/inet-showcases/tree/master/emulation/osudpVoip>`__

.. About VoIP
   ----------

   Voice over Internet Protocol (also voice over IP, VoIP or IP telephony)
   is a methodology and group of technologies for the delivery of voice
   communications and multimedia sessions over Internet Protocol (IP)
   networks, such as the Internet.

   VoIP uses codecs to encapsulate audio into data packets, transmit the
   packets across an IP network and decapsulate the packets back into
   audio at the other end of the connection. By eliminating the use of
   circuit-switched networks for voice, VoIP reduces network infrastructure
   costs, enables providers to deliver voice services over their broadband
   and private networks and allows enterprises to operate a single voice
   and data network.

The model
---------

- why is it good (?)
- voip stream

- INET is used to emulate VoIP traffic
- There are modules that do that realistically, that is they take a sound file, encode it, fragment it, and send it via UDP. On the other side, the sound file is reconstructed, while simulating VoIP effects, such as de-jitter buffering and discarding timed-out packets
- This showcase demonstrates this; the UDP packets are sent via the real network stack of the host OS
- The simulated sender and receiver could run on different machines, while the traffic is sent via the real network
- There are actually two emulation features here; VoIP encoding and traffic emulation, and UDP emulation

.. INET can be used to emulate VoIP traffic. The :ned:`VoipStreamSender` module can do that realistically, i.e. it can encode an audio file

.. The :ned:`VoipStreamSender` module can emulate realistic VoIP traffic. The module takes an audio file,

.. The module takes the contents of an audio file and transmits it as voip traffic.

The :ned:`VoipStreamSender` module transmits the contents of an audio file as voip traffic. It resamples the audio, encodes it with a codec, fragments it and sends the fragments via udp. By default, it creates 20 ms long fragments, and sends a fragment every 20 ms.

The :ned:`VoipStreamReceiver` module can receive this data stream, decode it and save it as an audio file.

- more details about the voip modules, such as simulating de jitter buffer
- what can be configured with parameters in the sender

The voip stream sender generates application packets, which are encapsulated in UDP packets and sent by the ext udp module. Simulated UDP packets enter the module, which injects them into the host OS protocol stack via a UDP socket.

.. figure:: media/setup.png
   :align: center
   :width: 60%

.. encodes it, fragments it and sends the fragments via UDP.

- the setup + ext udp
- schematic

- network
- configuration

TODO:

.. The ``ExtLowerUdp`` module makes it possible to divide the simulated model into
   two parts at the transport layer, exchange one part with real

.. The ``ExtLowerUdp`` module makes it possible for the model to be extracted
   from the simulation and be used in a real operating environment. The
   model executes the configured behavior in the real world while still
   producing the same statistics as used to.

The network
~~~~~~~~~~~

Usually a network in a simulation contains some nodes and connections in
between. In this case, it is different. Only a simulated sender
application and a simulated receiver application are needed in order to
send the packets into the real network on one side and receive them on
the other side.

There are only two modules per "network". There is a
``VoipStreamSender`` in the sender application and a
``VoipStreamReceiver`` in the receiver application, both called ``app``.
Both Applications contain a ``ExtLowerUdp`` module, called ``udp``. The
layout of the two applications can be seen in the following image:

+----------------------------------------------------+--+---------------------------------------------------+
|        Voip Stream Sender Application              |  |      Voip Stream Receiver Application             |
+====================================================+==+===================================================+
|.. image:: media/VoipStreamSenderApplication.png    |  |.. image:: media/VoipStreamReceiverApplication.png |
|   :width: 100%                                     |  |   :width: 100%                                    |
|   :align: center                                   |  |   :align: center                                  |
+----------------------------------------------------+--+---------------------------------------------------+

These two simulations work completely separated from each other, meaning
that they could also be run on different devices. However, for the sake
of simplicity, during this showcase both are run on the same computer.
As the names of the applications indicate, the
``VoipStreamSenderApplication`` produces a VoIP traffic and sends the
packets to the ``VoipStreamReceiverApplication`` as destination, while
the ``VoipStreamReceiverApplication`` receives and processes the VoIP
packets.

The simulation is run until all the packets arrive.

Configuration and behaviour
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``VoipStreamSender`` and ``VoipStreamReceiver`` modules are part of the
simulation. There is no difference in the configuration of these modules
compared to a fully simulated scenario. This means that the ``ExtLowerUdp``
module looks and behaves just like the ``UdpApp`` from the point of view
of the modules above them.

**VoipStreamSender:**

As stated above, in this showcase, both simulations are run on the same
computer. That is why the ``destAddress`` parameter is set to
``27.0.0.1`` address, called the loopback address, referring to *this
computer*.

.. literalinclude:: ../sender.ini
   :language: ini
   :start-at: packetTimeLength

The ``VoIP`` configuration is run in order to demonstrate that the sound
is actually transmitted from the sender to the receiver.

**VoipStreamReceiver:**

.. literalinclude:: ../receiver.ini
   :language: ini
   :start-at: localPort

Although the ``udp`` module is the key module of the emulation, it does
not need any configuration. This module acts as a bridge between the
simulated and the real world. When instead of ``UdpApp`` this ``ExtLowerUdp``
is used, it means that from that point on the emulation is running in
the real world. In this case it means that at the ``ExtLowerUdp`` the VoIP
traffic exits the simulation and enters the real operating environment
of the OS, and vice versa.

Another important point of the emulation is to set the
``RealTimeScheduler`` as the mean of synchronization:

.. literalinclude:: ../receiver.ini
   :language: ini
   :start-at: RealTimeScheduler
   :end-before: tkenv-plugin-path

Using this scheduler, the execution of the simulation is synchronized to
the real time of the CPU.

.. note::

   Operation of the real-time scheduler: a "base time" is
   determined when ``startRun()`` is called. Later on, the scheduler object
   calls ``usleep()`` from ``getNextEvent()`` to synchronize the simulation
   time to real time, that is, to wait until the current time minus base
   time becomes equal to the simulation time. Should the simulation lag
   behind real time, this scheduler will try to catch up by omitting sleep
   calls altogether.

Results
-------

Original music
~~~~~~~~~~~~~~

As a reference, you can listen to the original audio file by clicking
the play button below:


.. raw:: html

   <p><audio controls> <source src="media/original.mp3" type="audio/mpeg">Your browser does not support the audio tag.</audio></p>

This music is then sampled and forwarded by the ``VoipStreamSender``
module and received by the ``VoipStreamReceiver`` module. The packets
exit the simulation at the ``ExtLowerUdp`` of the sender side and enter the
other simulation at the ``ExtLowerUdp`` of the receiver side. In between the
packets travel across the real network (the computer's loopback
interface in our case).

**VoIP** configuration
~~~~~~~~~~~~~~~~~~~~~~

Due to the high sampling rate, the quality of the received sound is
nearly as good as of the original file:

.. raw:: html

   <p><audio controls> <source src="media/sound.wav" type="audio/wav">Your browser does not support the audio tag.</audio></p>

It is stated above that the two simulations run separately on the same
device using the computer's loopback interface. To provide some evidence
for supporting this statement, we can take a look at the network traffic
rate of the interfaces of the computer. The following video shows how
the traffic rate of the loopback interface (named ``lo``) changes while
the simulation is running:

.. video:: media/loopback.mp4
   :width: 100%
|

It is clearly visible that the traffic rate of the loopback interface
increases from the former value of zero to a higher, relatively constant
value, as soon as the sender side of the emulation is started. After the
end of the simulation, meaning that there are no more data to be sent,
the traffic rate falls back to zero.

Conclusion
----------

It is not necessary to rewrite the simulated model into a suitable form
for testing it in the real world. Using external interfaces, parts of a
simulation can easily be extracted into the real operating environment.
This feature of INET makes developing, simulating and testing much
simpler.

Further Information
-------------------

The following link provides more information about VoIP in general:
`VoIP <https://en.wikipedia.org/wiki/Voice_over_IP>`__

The network traffic was observed using
`bmon <https://github.com/tgraf/bmon>`__, which is a monitoring and
debugging tool to capture networking related statistics and prepare them
visually in a human-friendly way.

More information can be found in the `INET
Reference <https://omnetpp.org/doc/inet/api-current/neddoc/index.html>`__.

Discussion
----------

Use `this
page <https://github.com/inet-framework/inet-showcases/issues/??>`__ in
the GitHub issue tracker for commenting on this showcase.
