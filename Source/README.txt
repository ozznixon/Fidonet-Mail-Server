P L A N E T ~ Z E R O
=====================

Planet Zero is a Fidonet Mailer Package for Proboard L/X.
(C) 2026 by Brain Patchwork DX, LLC. All rights reserved, worldwide.
Author: G.E. Ozz Nixon Jr.
Latest Version: P0 v1.0.0 (March 7th 2026)

FrontEnd.dpr      Main program, INI config, CLI
FidoSock.pas      DXSock 6 adapter (TConnIO/TByteIO over TBPDXSock)
FidoMailer.pas    Session engine, poller, inbound server

FidoNet.pas       Core types, constants, CRC-16/32, address utils
FidoSession.pas   EMSI / YooHoo/2U2 / FTS-0001 session handshake
FidoPkt.pas       FTS-0001 type-2 PKT reader/writer + BSO bundle manager
FidoBark.pas      Bark FREQ file-request protocol (FTS-0008)

FidoZModem.pas    ZModem / ZedZap file transfer (sender + receiver)
FidoNodelist.pas  NODELIST.nnn parser + indexed lookup
FidoToss.pas      Inbound PKT tosser + outbound message scanner

