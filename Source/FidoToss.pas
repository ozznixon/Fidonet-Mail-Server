{ ==========================================================================
  FidoToss.pas — Inbound packet tosser and outbound scanner
  Tosser: reads .PKT files from inbound dir, routes to message areas
  Scanner: reads message areas, creates outbound .PKT bundles
  Uses simple text-file "message base" (one file per area) for portability.
  Replace TSimpleMsgBase with your own *.JAM / *.MSG adapter as needed.
  ========================================================================== }
unit FidoToss;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes, FidoNet, FidoPkt;

type
  { Minimal message base interface }
  IMsgBase = interface
    function  StoreMsg(const Msg: TFidoMsg): Boolean;
    function  ReadMsg(Index: Integer; var Msg: TFidoMsg): Boolean;
    function  MsgCount: Integer;
    function  AreaTag: string;
  end;

  { Area routing table entry }
  TAreaRoute = record
    AreaTag   : string;
    DestAddr  : TFidoAddr;
    Flavor    : AnsiChar;   { 'C'=Crash, 'O'=Normal, 'H'=Hold, 'D'=Direct }
    Password  : string;
  end;

  { Toss log entry }
  TTossLogEntry = record
    Filename : string;
    MsgCount : Integer;
    Errors   : Integer;
    Dupes    : Integer;
  end;

  { Simple flat-file message store (one .MSG directory per area) }
  TSimpleMsgBase = class(TInterfacedObject, IMsgBase)
  private
    FDir     : string;
    FAreaTag : string;
    FMsgList : TStringList;
    procedure LoadIndex;
  public
    constructor Create(const ADir, AAreaTag: string);
    destructor  Destroy; override;
    function  StoreMsg(const Msg: TFidoMsg): Boolean;
    function  ReadMsg(Index: Integer; var Msg: TFidoMsg): Boolean;
    function  MsgCount: Integer;
    function  AreaTag: string;
  end;

  { Tosser: processes inbound .PKT files }
  TTosser = class
  private
    FConfig   : TMailerConfig;
    FAreaMap  : TStringList;  { AreaTag -> path }
    FBadPkt   : string;
    FLog      : TTossLogEntry;
    FDupeFile : string;
    FDupes    : TStringList;

    procedure LoadDupes;
    procedure SaveDupes;
    function  IsDupe(const Msg: TFidoMsg): Boolean;
    procedure MarkDupe(const Msg: TFidoMsg);
    function  GetMsgBase(const AreaTag: string): TSimpleMsgBase;
    function  TossMsg(const Msg: TFidoMsg): Boolean;
    function  ValidatePacket(const Filename: string): Boolean;
  public
    constructor Create(const ACfg: TMailerConfig);
    destructor  Destroy; override;
    procedure   AddArea(const AreaTag, MsgDir: string);
    function    TossFile(const PktFile: string): TTossLogEntry;
    procedure   TossAll;
    property    BadPktDir: string read FBadPkt write FBadPkt;
  end;

  { Scanner: creates outbound .PKT bundles from message areas }
  TScanner = class
  private
    FConfig    : TMailerConfig;
    FRoutes    : array of TAreaRoute;
    FRouteCount: Integer;
    FBundles   : TBundleManager;

    function  FindRoute(const AreaTag: string;
      var Route: TAreaRoute): Boolean;
    function  ScanArea(Base: TSimpleMsgBase;
      const Route: TAreaRoute): Integer;
  public
    constructor Create(const ACfg: TMailerConfig);
    destructor  Destroy; override;
    procedure   AddRoute(const Route: TAreaRoute);
    function    ScanAll(Areas: TStringList): Integer;
  end;

implementation

{ ====================== TSimpleMsgBase ====================== }

constructor TSimpleMsgBase.Create(const ADir, AAreaTag: string);
begin
  inherited Create;
  FDir     := IncludeTrailingPathDelimiter(ADir);
  FAreaTag := AAreaTag;
  FMsgList := TStringList.Create;
  ForceDirectories(FDir);
  LoadIndex;
end;

destructor TSimpleMsgBase.Destroy;
begin
  FMsgList.Free;
  inherited;
end;

procedure TSimpleMsgBase.LoadIndex;
var
  SR: TSearchRec;
begin
  FMsgList.Clear;
  if FindFirst(FDir + '*.msg', faAnyFile, SR) = 0 then
  begin
    repeat
      FMsgList.Add(FDir + SR.Name);
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
  FMsgList.Sort;
end;

function TSimpleMsgBase.StoreMsg(const Msg: TFidoMsg): Boolean;
var
  Filename: string;
  F: TextFile;
  MsgNum: Integer;
begin
  Result := False;
  try
    MsgNum := FMsgList.Count + 1;
    Filename := FDir + Format('%.6d.msg', [MsgNum]);
    AssignFile(F, Filename);
    Rewrite(F);
    try
      WriteLn(F, 'FROM: ' + Msg.FromName);
      WriteLn(F, 'TO: ' + Msg.ToName);
      WriteLn(F, 'SUBJ: ' + Msg.Subject);
      WriteLn(F, 'DATE: ' + Msg.DateTime);
      WriteLn(F, 'ORIG: ' + FidoAddrToStr(Msg.OrigAddr));
      WriteLn(F, 'DEST: ' + FidoAddrToStr(Msg.DestAddr));
      WriteLn(F, 'ATTR: ' + IntToStr(Msg.Attr));
      WriteLn(F, 'AREA: ' + Msg.Area);
      WriteLn(F, 'MSGID: ' + HexLong(Msg.MsgId));
      WriteLn(F, '');
      WriteLn(F, Msg.Body);
    finally
      CloseFile(F);
    end;
    FMsgList.Add(Filename);
    Result := True;
  except
    Result := False;
  end;
end;

function TSimpleMsgBase.ReadMsg(Index: Integer;
  var Msg: TFidoMsg): Boolean;
var
  F: TextFile;
  Line, Key, Val: string;
  P: Integer;
  InBody: Boolean;
begin
  Result := False;
  if (Index < 0) or (Index >= FMsgList.Count) then Exit;
  FillChar(Msg, SizeOf(Msg), 0);
  try
    AssignFile(F, FMsgList[Index]);
    Reset(F);
    InBody := False;
    try
      while not EOF(F) do
      begin
        ReadLn(F, Line);
        if InBody then
        begin
          Msg.Body := Msg.Body + Line + #13;
          Continue;
        end;
        if Line = '' then
        begin
          InBody := True;
          Continue;
        end;
        P := Pos(': ', Line);
        if P = 0 then Continue;
        Key := UpperCase(Copy(Line,1,P-1));
        Val := Copy(Line,P+2,999);
        if Key = 'FROM'  then Msg.FromName := Val
        else if Key = 'TO'    then Msg.ToName   := Val
        else if Key = 'SUBJ'  then Msg.Subject  := Val
        else if Key = 'DATE'  then Msg.DateTime := Val
        else if Key = 'ORIG'  then StrToFidoAddr(Val, Msg.OrigAddr)
        else if Key = 'DEST'  then StrToFidoAddr(Val, Msg.DestAddr)
        else if Key = 'ATTR'  then Msg.Attr := StrToIntDef(Val,0)
        else if Key = 'AREA'  then Msg.Area := Val
        else if Key = 'MSGID' then Msg.MsgId := StrToIntDef('$'+Val,0);
      end;
      Result := True;
    finally
      CloseFile(F);
    end;
  except
    Result := False;
  end;
end;

function TSimpleMsgBase.MsgCount: Integer;
begin
  Result := FMsgList.Count;
end;

function TSimpleMsgBase.AreaTag: string;
begin
  Result := FAreaTag;
end;

{ ====================== TTosser ====================== }

constructor TTosser.Create(const ACfg: TMailerConfig);
begin
  inherited Create;
  FConfig  := ACfg;
  FAreaMap := TStringList.Create;
  FDupes   := TStringList.Create;
  FBadPkt  := IncludeTrailingPathDelimiter(ACfg.InboundDir) + 'BAD' + PathDelim;
  FDupeFile:= IncludeTrailingPathDelimiter(ACfg.InboundDir) + 'DUPES.TXT';
  LoadDupes;
end;

destructor TTosser.Destroy;
begin
  SaveDupes;
  FDupes.Free;
  FAreaMap.Free;
  inherited;
end;

procedure TTosser.LoadDupes;
begin
  if FileExists(FDupeFile) then
    FDupes.LoadFromFile(FDupeFile);
end;

procedure TTosser.SaveDupes;
begin
  FDupes.SaveToFile(FDupeFile);
end;

function TTosser.IsDupe(const Msg: TFidoMsg): Boolean;
var
  Key: string;
begin
  Key := FidoAddrToStr(Msg.OrigAddr) + ':' + HexLong(Msg.MsgId);
  Result := FDupes.IndexOf(Key) >= 0;
end;

procedure TTosser.MarkDupe(const Msg: TFidoMsg);
var
  Key: string;
begin
  Key := FidoAddrToStr(Msg.OrigAddr) + ':' + HexLong(Msg.MsgId);
  if FDupes.Count > 5000 then
    FDupes.Delete(0);
  FDupes.Add(Key);
end;

procedure TTosser.AddArea(const AreaTag, MsgDir: string);
begin
  FAreaMap.Values[UpperCase(AreaTag)] := MsgDir;
end;

function TTosser.GetMsgBase(const AreaTag: string): TSimpleMsgBase;
var
  Dir: string;
begin
  Dir := FAreaMap.Values[UpperCase(AreaTag)];
  if Dir = '' then
    Dir := IncludeTrailingPathDelimiter(FConfig.InboundDir) +
      'UNKNOWN' + PathDelim + AreaTag;
  Result := TSimpleMsgBase.Create(Dir, AreaTag);
end;

function TTosser.ValidatePacket(const Filename: string): Boolean;
{ Basic check: file exists and is at least header size }
begin
  Result := FileExists(Filename) and
    (TFileStream.Create(Filename, fmOpenRead).Size >=
     SizeOf(TPacketHeader));
end;

function TTosser.TossMsg(const Msg: TFidoMsg): Boolean;
var
  Base: TSimpleMsgBase;
begin
  Result := False;
  if IsDupe(Msg) then
  begin
    Inc(FLog.Dupes);
    Result := True;  { dupe is not an error }
    Exit;
  end;
  Base := GetMsgBase(Msg.Area);
  try
    if Base.StoreMsg(Msg) then
    begin
      MarkDupe(Msg);
      Inc(FLog.MsgCount);
      Result := True;
    end else
      Inc(FLog.Errors);
  finally
    Base.Free;
  end;
end;

function TTosser.TossFile(const PktFile: string): TTossLogEntry;
var
  Rdr: TPacketReader;
  Msg: TFidoMsg;
  BakFile: string;
begin
  FillChar(FLog, SizeOf(FLog), 0);
  FLog.Filename := PktFile;
  if not ValidatePacket(PktFile) then
  begin
    Inc(FLog.Errors);
    Result := FLog;
    Exit;
  end;
  Rdr := TPacketReader.Create(PktFile);
  try
    while Rdr.ReadNextMsg(Msg) do
      TossMsg(Msg);
  finally
    Rdr.Free;
  end;
  if FLog.Errors = 0 then
    DeleteFile(PktFile)
  else
  begin
    ForceDirectories(FBadPkt);
    BakFile := FBadPkt + ExtractFilename(PktFile);
    RenameFile(PktFile, BakFile);
  end;
  Result := FLog;
end;

procedure TTosser.TossAll;
var
  SR: TSearchRec;
  Dir: string;
begin
  Dir := IncludeTrailingPathDelimiter(FConfig.InboundDir);
  if FindFirst(Dir + '*.PKT', faAnyFile, SR) = 0 then
  begin
    repeat
      TossFile(Dir + SR.Name);
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
end;

{ ====================== TScanner ====================== }

constructor TScanner.Create(const ACfg: TMailerConfig);
begin
  inherited Create;
  FConfig     := ACfg;
  FRouteCount := 0;
  FBundles    := TBundleManager.Create(ACfg);
end;

destructor TScanner.Destroy;
begin
  FBundles.Free;
  inherited;
end;

procedure TScanner.AddRoute(const Route: TAreaRoute);
begin
  if FRouteCount >= Length(FRoutes) then
    SetLength(FRoutes, Max(8, Length(FRoutes)*2));
  FRoutes[FRouteCount] := Route;
  Inc(FRouteCount);
end;

function TScanner.FindRoute(const AreaTag: string;
  var Route: TAreaRoute): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to FRouteCount-1 do
    if UpperCase(FRoutes[I].AreaTag) = UpperCase(AreaTag) then
    begin
      Route := FRoutes[I];
      Result := True;
      Exit;
    end;
end;

function TScanner.ScanArea(Base: TSimpleMsgBase;
  const Route: TAreaRoute): Integer;
var
  Msg: TFidoMsg;
  Pkt: TPacketWriter;
  I: Integer;
  Sent: Integer;
begin
  Sent := 0;
  if Base.MsgCount = 0 then
  begin
    Result := 0; Exit;
  end;
  Pkt := FBundles.OpenOutPkt(Route.DestAddr,
    Route.Flavor, Route.Password);
  try
    for I := 0 to Base.MsgCount-1 do
    begin
      if Base.ReadMsg(I, Msg) then
      begin
        Pkt.WriteMessage(Msg);
        Inc(Sent);
      end;
    end;
  finally
    if Sent > 0 then
      FBundles.StorePktBundle(Pkt.Filename, Route.DestAddr, Route.Flavor);
    Pkt.Free;
  end;
  Result := Sent;
end;

function TScanner.ScanAll(Areas: TStringList): Integer;
{ Areas: Name=Path list, e.g. "ECHOZONE1=/var/msgs/zone1" }
var
  I: Integer;
  Tag, Dir: string;
  Base: TSimpleMsgBase;
  Route: TAreaRoute;
  Total: Integer;
begin
  Total := 0;
  for I := 0 to Areas.Count-1 do
  begin
    Tag := Areas.Names[I];
    Dir := Areas.ValueFromIndex[I];
    if not FindRoute(Tag, Route) then Continue;
    Base := TSimpleMsgBase.Create(Dir, Tag);
    try
      Inc(Total, ScanArea(Base, Route));
    finally
      Base.Free;
    end;
  end;
  Result := Total;
end;

end.
