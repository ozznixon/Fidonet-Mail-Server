{ ==========================================================================
  FrontEnd.pas — Free Pascal Fidonet Mailer — Main program
  Usage:
    FrontEnd --config <file.ini>   Run mailer (listen + poll)
    FrontEnd --poll <zone:net/node>  Poll specific node
    FrontEnd --toss                  Toss inbound PKT files only
    FrontEnd --scan                  Scan outbound message areas only
    FrontEnd --help
  ========================================================================== }
program FPMailer;

{$IFDEF FPC}{$MODE DELPHI}{$ELSE}
{$DEFINE DELPHI}
{$APPTYPE CONSOLE}
{$ENDIF}
{$H+}

uses
  SysUtils, Classes,
  FidoNet,      {Core types, Constants, CRC, Address Helper}
  FidoPkt,      {FTS-0001 Type 2/2.2 PKT Reader/Write + BSO Helper}
  FidoSession,  {EMSI, YooHoo/2u2, FTS-0001 Session Handshakes}
  FidoZModem,   {ZModem/ZedZap file transfer (sender/receiver)}
  FidoBark,     {Bark FREQ (File Request Protocol) FTS-0008}
  FidoNodelist, {FTN NODELIST.nnn Parser and Indexed Lookup}
  FidoToss,     {Inbound PKT tosser and outbound message scanner}
  FidoSock,     {DXSock/6 Adapter (TConnIO/TByteIO over TBPDXSock)}
  FidoMailer;   {Session Engine, Poller, Inbound Server}

const
  CONFIG_FILE = 'frontend.ini';
  VERSION     = '1.0';

type
  TAppConfig = record
    Mailer   : TMailerConfig;
    Areas    : TStringList;
    Routes   : array of TAreaRoute;
    RouteCount: Integer;
    PollList : array of TPollEntry;
    PollCount: Integer;
  end;

var
  GConfig : TAppConfig;
  GLog    : TStringList;

{ ---------- logging ---------- }

procedure WriteLog(Level: TLogLevel; const Msg: string);
const
  LTag: array[TLogLevel] of string = ('DBG','INF','WRN','ERR');
var
  Line: string;

begin
   Line := FormatDateTime('YYYY-MM-DD HH:NN:SS', Now) +
      ' [' + LTag[Level] + '] ' + Msg;
   WriteLn(Line);
   if Assigned(GLog) then
      GLog.Add(Line);
end;

procedure FlushLog;
begin
  if Assigned(GLog) and (GConfig.Mailer.LogFile <> '') then
  begin
    var F: TextFile;
    AssignFile(F, GConfig.Mailer.LogFile);
    if FileExists(GConfig.Mailer.LogFile) then
      Append(F)
    else
      Rewrite(F);
    try
      var I: Integer;
      for I := 0 to GLog.Count-1 do
        WriteLn(F, GLog[I]);
    finally
      CloseFile(F);
    end;
    GLog.Clear;
  end;
end;

{ ---------- INI parser ---------- }

procedure LoadConfig(const Filename: string);
var
  INI   : TStringList;
  Line, Key, Val, Section: string;
  I, P  : Integer;
  Route : TAreaRoute;
  Poll  : TPollEntry;
begin
  if not FileExists(Filename) then
  begin
    WriteLn('Config file not found: ', Filename);
    Halt(1);
  end;
  INI := TStringList.Create;
  INI.LoadFromFile(Filename);
  Section := '';
  { Defaults }
  GConfig.Mailer.ListenPort    := 24554;
  GConfig.Mailer.MaxSessions   := 8;
  GConfig.Mailer.SessionTimeout:= 300;
  GConfig.Mailer.ConnectTimeout:= 60;
  GConfig.Mailer.AnswerDelay   := 500;
  GConfig.Areas    := TStringList.Create;
  GConfig.RouteCount := 0;
  GConfig.PollCount  := 0;

  for I := 0 to INI.Count-1 do
  begin
    Line := Trim(INI[I]);
    if (Line = '') or (Line[1] = ';') or (Line[1] = '#') then Continue;
    if (Line[1] = '[') then
    begin
      Section := UpperCase(Copy(Line,2,Length(Line)-2));
      Continue;
    end;
    P := Pos('=', Line);
    if P = 0 then Continue;
    Key := UpperCase(Trim(Copy(Line,1,P-1)));
    Val := Trim(Copy(Line,P+1,999));

    if Section = 'IDENTITY' then
    begin
      if Key = 'ADDRESS'    then StrToFidoAddr(Val, GConfig.Mailer.Address);
      if Key = 'SYSOPNAME'  then GConfig.Mailer.SysOpName   := Val;
      if Key = 'SYSTEMNAME' then GConfig.Mailer.SystemName  := Val;
      if Key = 'LOCATION'   then GConfig.Mailer.Location    := Val;
      if Key = 'PHONE'      then GConfig.Mailer.Phone       := Val;
      if Key = 'PASSWORD'   then GConfig.Mailer.Password    := Val;
    end
    else if Section = 'PATHS' then
    begin
      if Key = 'INBOUND'    then GConfig.Mailer.InboundDir  := Val;
      if Key = 'OUTBOUND'   then GConfig.Mailer.OutboundDir := Val;
      if Key = 'NETMAIL'    then GConfig.Mailer.NetMailDir  := Val;
      if Key = 'NODELIST'   then GConfig.Mailer.NodelistDir := Val;
      if Key = 'TEMP'       then GConfig.Mailer.TempDir     := Val;
      if Key = 'LOG'        then GConfig.Mailer.LogFile     := Val;
    end
    else if Section = 'SESSION' then
    begin
      if Key = 'PORT'       then GConfig.Mailer.ListenPort  := StrToIntDef(Val,24554);
      if Key = 'MAXSESSIONS'then GConfig.Mailer.MaxSessions := StrToIntDef(Val,8);
      if Key = 'TIMEOUT'    then GConfig.Mailer.SessionTimeout := StrToIntDef(Val,300);
      if Key = 'CONNECTTIMEOUT' then GConfig.Mailer.ConnectTimeout := StrToIntDef(Val,60);
    end
    else if Section = 'AREAS' then
    begin
      { AREA_TAG=path }
      GConfig.Areas.Values[UpperCase(Key)] := Val;
    end
    else if Section = 'ROUTES' then
    begin
      { AREA_TAG=zone:net/node,C,password }
      var Parts := TStringList.Create;
      try
        Parts.Delimiter := ',';
        Parts.DelimitedText := Val;
        if Parts.Count >= 2 then
        begin
          if GConfig.RouteCount >= Length(GConfig.Routes) then
            SetLength(GConfig.Routes,
              Max(8, Length(GConfig.Routes)*2));
          Route.AreaTag  := UpperCase(Key);
          StrToFidoAddr(Parts[0], Route.DestAddr);
          Route.Flavor   := AnsiChar(UpperCase(Parts[1])[1]);
          if Parts.Count > 2 then
            Route.Password := Parts[2];
          GConfig.Routes[GConfig.RouteCount] := Route;
          Inc(GConfig.RouteCount);
        end;
      finally
        Parts.Free;
      end;
    end
    else if Section = 'POLL' then
    begin
      { zone:net/node=host[:port],password,C }
      var Parts := TStringList.Create;
      try
        Parts.Delimiter := ',';
        Parts.DelimitedText := Val;
        if GConfig.PollCount >= Length(GConfig.PollList) then
          SetLength(GConfig.PollList,
            Max(8, Length(GConfig.PollList)*2));
        FillChar(Poll, SizeOf(Poll), 0);
        StrToFidoAddr(Key, Poll.Addr);
        if Parts.Count > 0 then Poll.Phone    := Parts[0];
        if Parts.Count > 1 then Poll.Password := Parts[1];
        if Parts.Count > 2 then Poll.Flavor   := AnsiChar(UpperCase(Parts[2])[1])
        else Poll.Flavor := 'O';
        GConfig.PollList[GConfig.PollCount] := Poll;
        Inc(GConfig.PollCount);
      finally
        Parts.Free;
      end;
    end;
  end;
  INI.Free;
  { ensure dirs exist }
  ForceDirectories(GConfig.Mailer.InboundDir);
  ForceDirectories(GConfig.Mailer.OutboundDir);
  ForceDirectories(GConfig.Mailer.TempDir);
end;

{ ---------- write sample config ---------- }

procedure WriteSampleConfig(const Filename: string);
var
  F: TextFile;
begin
  AssignFile(F, Filename);
  Rewrite(F);
  WriteLn(F, '; FrontEnd configuration file');
  WriteLn(F, '; Generated by FrontEnd v' + VERSION);
  WriteLn(F, '');
  WriteLn(F, '[Identity]');
  WriteLn(F, 'Address      = 1:100/200');
  WriteLn(F, 'SysOpName    = Firstname Lastname');
  WriteLn(F, 'SystemName   = My BBS');
  WriteLn(F, 'Location     = City, Country');
  WriteLn(F, 'Phone        = 000-000-0000');
  WriteLn(F, 'Password     = mypassword');
  WriteLn(F, '');
  WriteLn(F, '[Paths]');
  WriteLn(F, 'Inbound  = /var/fido/inbound');
  WriteLn(F, 'Outbound = /var/fido/outbound');
  WriteLn(F, 'Netmail  = /var/fido/netmail');
  WriteLn(F, 'Nodelist = /var/fido/nodelist');
  WriteLn(F, 'Temp     = /tmp/fpmailer');
  WriteLn(F, 'Log      = /var/log/fpmailer.log');
  WriteLn(F, '');
  WriteLn(F, '[Session]');
  WriteLn(F, 'Port            = 24554');
  WriteLn(F, 'MaxSessions     = 8');
  WriteLn(F, 'Timeout         = 300');
  WriteLn(F, 'ConnectTimeout  = 60');
  WriteLn(F, '');
  WriteLn(F, '; Area tag to message directory mapping');
  WriteLn(F, '[Areas]');
  WriteLn(F, 'NETMAIL     = /var/fido/netmail');
  WriteLn(F, 'GENERAL     = /var/fido/msgs/general');
  WriteLn(F, 'FIDODEV     = /var/fido/msgs/fidodev');
  WriteLn(F, '');
  WriteLn(F, '; Routing: AreaTag = DestAddr,Flavor,Password');
  WriteLn(F, '; Flavor: C=Crash O=Normal H=Hold D=Direct');
  WriteLn(F, '[Routes]');
  WriteLn(F, 'NETMAIL = 1:100/100,C,hubpassword');
  WriteLn(F, 'GENERAL = 1:100/100,O');
  WriteLn(F, '');
  WriteLn(F, '; Polling: DestAddr = host[:port],password,Flavor');
  WriteLn(F, '[Poll]');
  WriteLn(F, '1:100/100 = bbs.example.com:24554,hubpass,O');
  CloseFile(F);
  WriteLn('Sample config written to: ', Filename);
end;

{ ---------- command dispatch ---------- }

procedure RunToss;
var
  T: TTosser;
begin
  WriteLog(llInfo, 'Tossing inbound packets...');
  T := TTosser.Create(GConfig.Mailer);
  try
    var I: Integer;
    for I := 0 to GConfig.Areas.Count-1 do
      T.AddArea(GConfig.Areas.Names[I],
        GConfig.Areas.ValueFromIndex[I]);
    T.TossAll;
  finally
    T.Free;
  end;
  WriteLog(llInfo, 'Toss complete.');
end;

procedure RunScan;
var
  S: TScanner;
  I: Integer;
begin
  WriteLog(llInfo, 'Scanning outbound message areas...');
  S := TScanner.Create(GConfig.Mailer);
  try
    for I := 0 to GConfig.RouteCount-1 do
      S.AddRoute(GConfig.Routes[I]);
    var N := S.ScanAll(GConfig.Areas);
    WriteLog(llInfo, Format('Scanned %d message(s)', [N]));
  finally
    S.Free;
  end;
end;

procedure RunPoll(const AddrStr: string);
var
  Addr: TFidoAddr;
  NL: TNodelistManager;
  Poller: TMailerPoller;
begin
  if not StrToFidoAddr(AddrStr, Addr) then
  begin
    WriteLn('Invalid address: ', AddrStr);
    Halt(1);
  end;
  NL := TNodelistManager.Create(GConfig.Mailer.NodelistDir);
  NL.LoadAll;
  Poller := TMailerPoller.Create(GConfig.Mailer, NL);
  try
    Poller.OnLog := @WriteLog;
    Poller.AddPoll(Addr,'','','O');
    Poller.RunOnce;
  finally
    Poller.Free;
    NL.Free;
  end;
end;

procedure RunServer;
var
  NL     : TNodelistManager;
  Server : TMailerServer;
  Poller : TMailerPoller;
  I      : Integer;
begin
  NL := TNodelistManager.Create(GConfig.Mailer.NodelistDir);
  NL.LoadAll;
  Server := TMailerServer.Create(GConfig.Mailer, NL);
  Server.OnLog := @WriteLog;
  Poller := TMailerPoller.Create(GConfig.Mailer, NL);
  Poller.OnLog := @WriteLog;
  try
    for I := 0 to GConfig.PollCount-1 do
      with GConfig.PollList[I] do
        Poller.AddPoll(Addr, Phone, Password, Flavor);
    WriteLog(llInfo, Format(
      'FPMailer v%s starting — %s — port %d',
      [VERSION,
       FidoAddrToStr(GConfig.Mailer.Address),
       GConfig.Mailer.ListenPort]));
    Server.StartInBackground;
    WriteLog(llInfo, 'Listening for inbound sessions...');
    { Run poll loop in foreground }
    Poller.Start;   { blocks until Ctrl-C }
  finally
    Server.Stop;
    Poller.Free;
    Server.Free;
    NL.Free;
  end;
end;

procedure ShowHelp;
begin
  WriteLn('FPMailer v', VERSION, ' — Free Pascal Fidonet Mailer');
  WriteLn('');
  WriteLn('Usage:');
  WriteLn('  fpmailer                       Run mailer (listen + poll)');
  WriteLn('  fpmailer --config <file>       Use specified config file');
  WriteLn('  fpmailer --poll <zone:net/node>  Poll specific node');
  WriteLn('  fpmailer --toss                Toss inbound PKT files only');
  WriteLn('  fpmailer --scan                Scan outbound areas only');
  WriteLn('  fpmailer --genconfig           Write sample fpmailer.ini');
  WriteLn('  fpmailer --help                Show this help');
  WriteLn('');
  WriteLn('Protocols: EMSI, YooHoo/2U2, FTS-0001, ZModem/ZedZap, BARK FREQ');
  WriteLn('Network:   DXSock 6 TCP/IP (FidoNet-over-IP / BSO outbound)');
end;

{ ---------- main ---------- }

var
  ConfigFile : string;
  CmdMode    : string;
  CmdArg     : string;
  I          : Integer;
  P:String;

begin
  GLog := TStringList.Create;
  ConfigFile := CONFIG_FILE;
  CmdMode    := 'run';
  CmdArg     := '';

  I := 1;
  while I <= ParamCount do begin
    P := LowerCase(ParamStr(I));
    if (P = '--config') and (I < ParamCount) then begin
       Inc(I);
       ConfigFile := ParamStr(I);
    end
    else if P = '--toss'  then CmdMode := 'toss'
    else if P = '--scan'  then CmdMode := 'scan'
    else if P = '--help'  then CmdMode := 'help'
    else if P = '--genconfig' then CmdMode := 'genconfig'
    else if (P = '--poll') and (I < ParamCount) then
    begin
      CmdMode := 'poll';
      Inc(I);
      CmdArg := ParamStr(I);
    end;
    Inc(I);
  end;

  case CmdMode of
    'help'      : begin ShowHelp; Halt(0); end;
    'genconfig' : begin WriteSampleConfig(ConfigFile); Halt(0); end;
  end;

  LoadConfig(ConfigFile);

  case CmdMode of
    'toss' : RunToss;
    'scan' : RunScan;
    'poll' : RunPoll(CmdArg);
    'run'  : RunServer;
  end;

  FlushLog;
  GLog.Free;
  if Assigned(GConfig.Areas) then GConfig.Areas.Free;
end.
