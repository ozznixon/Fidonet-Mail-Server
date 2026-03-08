{ ==========================================================================
  FidoPkt.pas — FTS-0001 type-2 packet reader and writer
  Handles .PKT files (message bundles)
  ========================================================================== }
unit FidoPkt;

{$MODE DELPHI}
{$PACKRECORDS 1}

interface

uses
  SysUtils, Classes, FidoNet;

type
  { Packet writer }
  TPacketWriter = class
  private
    FStream   : TFileStream;
    FFilename : string;
    FConfig   : TMailerConfig;
    FDest     : TFidoAddr;
    FPassword : string;
    FMsgCount : Integer;
    procedure WriteHeader;
  public
    constructor Create(const AFilename: string;
      const ACfg: TMailerConfig; const ADest: TFidoAddr;
      const APwd: string);
    destructor Destroy; override;
    procedure WriteMessage(const Msg: TFidoMsg);
    procedure Finish;
    property Filename: string read FFilename;
    property MsgCount: Integer read FMsgCount;
  end;

  { Packet reader }
  TPacketReader = class
  private
    FStream   : TFileStream;
    FFilename : string;
    FHeader   : TPacketHeader;
    FHeaderOK : Boolean;
    procedure ReadHeader;
  public
    constructor Create(const AFilename: string);
    destructor Destroy; override;
    function  ReadNextMsg(var Msg: TFidoMsg): Boolean;
    function  AtEnd: Boolean;
    property  Header: TPacketHeader read FHeader;
    property  OrigAddr: TFidoAddr read FHeader.OrigNode; { use GetOrigAddr }
    function  GetOrigAddr: TFidoAddr;
    function  GetDestAddr: TFidoAddr;
    property  Filename: string read FFilename;
  end;

  { High-level bundle manager }
  TBundleManager = class
  private
    FConfig : TMailerConfig;
    function BundlePath(const Dest: TFidoAddr; Flavor: AnsiChar): string;
    function BundleExt(Flavor: AnsiChar): string;
  public
    constructor Create(const ACfg: TMailerConfig);
    { Scan outbound dir, return list of .PKT/.?UT bundles to send to Dest }
    procedure GetOutboundFiles(const Dest: TFidoAddr;
      List: TStringList);
    { Create/append a .PKT for addr in outbound }
    function  OpenOutPkt(const Dest: TFidoAddr;
      Flavor: AnsiChar; const Password: string): TPacketWriter;
    { Mark bundle as sent — rename .OUT -> .BSY then delete }
    procedure MarkSent(const AFile: string);
    { Rename .PKT -> crash/normal/hold .?UT bundle }
    procedure StorePktBundle(const PktFile: string;
      const Dest: TFidoAddr; Flavor: AnsiChar);
  end;

function NewMsgID: LongWord;

implementation

var
  GMsgIDCounter: LongWord = 0;

function NewMsgID: LongWord;
begin
  if GMsgIDCounter = 0 then
    GMsgIDCounter := LongWord(Now * 86400);
  Inc(GMsgIDCounter);
  Result := GMsgIDCounter;
end;

{ ---------- TPacketWriter ---------- }

constructor TPacketWriter.Create(const AFilename: string;
  const ACfg: TMailerConfig; const ADest: TFidoAddr; const APwd: string);
begin
  inherited Create;
  FFilename := AFilename;
  FConfig   := ACfg;
  FDest     := ADest;
  FPassword := APwd;
  FMsgCount := 0;
  FStream   := TFileStream.Create(AFilename, fmCreate);
  WriteHeader;
end;

destructor TPacketWriter.Destroy;
begin
  Finish;
  FStream.Free;
  inherited;
end;

procedure TPacketWriter.WriteHeader;
var
  Hdr: TPacketHeader;
  DT: TDateTime;
  Y,Mo,D,H,Mi,S,Ms: Word;
begin
  ZeroMemBlock(Hdr, SizeOf(Hdr));
  DT := Now;
  DecodeDate(DT, Y, Mo, D);
  DecodeTime(DT, H, Mi, S, Ms);
  Hdr.OrigNode   := FConfig.Address.Node;
  Hdr.DestNode   := FDest.Node;
  Hdr.Year       := Y;
  Hdr.Month      := Mo - 1;   { 0-based }
  Hdr.Day        := D;
  Hdr.Hour       := H;
  Hdr.Minute     := Mi;
  Hdr.Second     := S;
  Hdr.Baud       := 0;
  Hdr.PktVersion := PKT_VERSION_2;
  Hdr.OrigNet    := FConfig.Address.Net;
  Hdr.DestNet    := FDest.Net;
  Hdr.ProdCode   := $FE;      { non-standard / free Pascal mailer }
  Hdr.SerialNo   := 0;
  if Length(FPassword) > 0 then
    Move(FPassword[1], Hdr.Password,
      Min(Length(FPassword), 8));
  Hdr.OrigZone   := FConfig.Address.Zone;
  Hdr.DestZone   := FDest.Zone;
  Hdr.AuxNet     := FConfig.Address.Net;
  Hdr.CWValidCopy:= $0100;
  Hdr.ProdCodeHi := 0;
  Hdr.RevMajor   := 1;
  Hdr.CapWord    := $0001;
  Hdr.OrigZone2  := FConfig.Address.Zone;
  Hdr.DestZone2  := FDest.Zone;
  Hdr.OrigPoint  := FConfig.Address.Point;
  Hdr.DestPoint  := FDest.Point;
  FStream.WriteBuffer(Hdr, SizeOf(Hdr));
end;

procedure TPacketWriter.WriteMessage(const Msg: TFidoMsg);
var
  MHdr  : TMsgHeader;
  W2    : SmallInt;
  Body  : AnsiString;
  NullB : Byte;
begin
  ZeroMemBlock(MHdr, SizeOf(MHdr));
  MHdr.PktVersion := PKT_VERSION_2;
  MHdr.OrigNode   := Msg.OrigAddr.Node;
  MHdr.DestNode   := Msg.DestAddr.Node;
  MHdr.OrigNet    := Msg.OrigAddr.Net;
  MHdr.DestNet    := Msg.DestAddr.Net;
  MHdr.Attr       := Msg.Attr;
  MHdr.Cost       := Msg.Cost;
  if Length(Msg.DateTime) > 0 then
    Move(Msg.DateTime[1], MHdr.DateTime,
      Min(Length(Msg.DateTime),19))
  else
  begin
    Body := Now5D;
    Move(Body[1], MHdr.DateTime, Min(Length(Body),19));
  end;
  FStream.WriteBuffer(MHdr, SizeOf(MHdr));
  { ASCIIZ strings: ToName, FromName, Subject }
  FStream.WriteBuffer(Msg.ToName[1], Length(Msg.ToName));
  NullB := 0; FStream.WriteBuffer(NullB, 1);
  FStream.WriteBuffer(Msg.FromName[1], Length(Msg.FromName));
  NullB := 0; FStream.WriteBuffer(NullB, 1);
  FStream.WriteBuffer(Msg.Subject[1], Length(Msg.Subject));
  NullB := 0; FStream.WriteBuffer(NullB, 1);
  { message body — build with kludges }
  Body := '';
  if Msg.Area <> '' then
    Body := Body + 'AREA:' + Msg.Area + #13
  else
  begin
    { INTL kludge for zone routing }
    if (Msg.OrigAddr.Zone <> 0) or (Msg.DestAddr.Zone <> 0) then
      Body := Body + #1 + 'INTL ' +
        FidoAddrToStr(Msg.DestAddr) + ' ' +
        FidoAddrToStr(Msg.OrigAddr) + #13;
    { FMPT for originating point }
    if Msg.OrigAddr.Point <> 0 then
      Body := Body + #1 + 'FMPT ' +
        IntToStr(Msg.OrigAddr.Point) + #13;
    { TOPT for destination point }
    if Msg.DestAddr.Point <> 0 then
      Body := Body + #1 + 'TOPT ' +
        IntToStr(Msg.DestAddr.Point) + #13;
  end;
  { MSGID kludge }
  Body := Body + #1 + 'MSGID: ' +
    FidoAddrToStr(Msg.OrigAddr) + ' ' +
    HexLong(Msg.MsgId) + #13;
  Body := Body + Msg.Body;
  if (Length(Body) = 0) or (Body[Length(Body)] <> #0) then
    Body := Body + #0;
  FStream.WriteBuffer(Body[1], Length(Body));
  Inc(FMsgCount);
end;

procedure TPacketWriter.Finish;
var
  Term: SmallInt;
begin
  if Assigned(FStream) then
  begin
    Term := 0;
    FStream.WriteBuffer(Term, 2);  { terminator }
  end;
end;

{ ---------- TPacketReader ---------- }

constructor TPacketReader.Create(const AFilename: string);
begin
  inherited Create;
  FFilename := AFilename;
  FStream   := TFileStream.Create(AFilename, fmOpenRead or fmShareDenyWrite);
  ReadHeader;
end;

destructor TPacketReader.Destroy;
begin
  FStream.Free;
  inherited;
end;

procedure TPacketReader.ReadHeader;
begin
  FHeaderOK := False;
  if FStream.Size < SizeOf(TPacketHeader) then Exit;
  FStream.ReadBuffer(FHeader, SizeOf(TPacketHeader));
  FHeaderOK := (FHeader.PktVersion = PKT_VERSION_2);
end;

function TPacketReader.ReadNextMsg(var Msg: TFidoMsg): Boolean;
var
  MHdr  : TMsgHeader;
  W     : SmallInt;
  S     : AnsiString;
  B     : Byte;
  Body  : AnsiString;
  Line  : AnsiString;
  P     : Integer;

  function ReadASCIIZ: AnsiString;
  var
    C: AnsiChar;
    Res: AnsiString;
  begin
    Res := '';
    while FStream.Read(C, 1) = 1 do
    begin
      if C = #0 then Break;
      Res := Res + C;
    end;
    Result := Res;
  end;

begin
  Result := False;
  if not FHeaderOK then Exit;
  if FStream.Position >= FStream.Size - 1 then Exit;
  { peek at next word — if 0 it is the terminator }
  if FStream.Read(W, 2) < 2 then Exit;
  if W = 0 then Exit;
  { put the 2 bytes into MHdr — they are PktVersion }
  ZeroMemBlock(Msg, SizeOf(Msg));
  MHdr.PktVersion := W;
  FStream.ReadBuffer(MHdr.OrigNode,
    SizeOf(TMsgHeader) - SizeOf(SmallInt));
  Msg.OrigAddr.Zone  := FHeader.OrigZone;
  Msg.OrigAddr.Net   := MHdr.OrigNet;
  Msg.OrigAddr.Node  := MHdr.OrigNode;
  Msg.OrigAddr.Point := FHeader.OrigPoint;
  Msg.DestAddr.Zone  := FHeader.DestZone;
  Msg.DestAddr.Net   := MHdr.DestNet;
  Msg.DestAddr.Node  := MHdr.DestNode;
  Msg.DestAddr.Point := FHeader.DestPoint;
  Msg.Attr           := MHdr.Attr;
  Msg.Cost           := MHdr.Cost;
  SetString(Msg.DateTime, MHdr.DateTime[0], 20);
  Msg.ToName   := ReadASCIIZ;
  Msg.FromName := ReadASCIIZ;
  Msg.Subject  := ReadASCIIZ;
  Body := ReadASCIIZ;
  { parse kludges out of body }
  Msg.Body := '';
  P := 1;
  while P <= Length(Body) do
  begin
    { find end of line }
    S := '';
    while (P <= Length(Body)) and (Body[P] <> #13) do
    begin
      S := S + Body[P];
      Inc(P);
    end;
    if (P <= Length(Body)) and (Body[P] = #13) then Inc(P);
    if (Length(S) > 0) and (S[1] = #1) then
    begin
      { kludge line }
      Line := Copy(S,2,999);
      if Copy(Line,1,5) = 'INTL ' then
      begin
        { parse zone addresses }
      end
      else if Copy(Line,1,7) = 'MSGID: ' then
        Msg.MsgId := StrToIntDef('$'+Copy(Line,15,8), 0)
      else if Copy(Line,1,5) = 'FMPT ' then
        Msg.OrigAddr.Point := StrToIntDef(Copy(Line,6,99),0)
      else if Copy(Line,1,5) = 'TOPT ' then
        Msg.DestAddr.Point := StrToIntDef(Copy(Line,6,99),0);
    end
    else if Copy(S,1,5) = 'AREA:' then
      Msg.Area := Trim(Copy(S,6,999))
    else
      Msg.Body := Msg.Body + S + #13;
  end;
  Result := True;
end;

function TPacketReader.AtEnd: Boolean;
begin
  Result := FStream.Position >= FStream.Size - 2;
end;

function TPacketReader.GetOrigAddr: TFidoAddr;
begin
  Result.Zone  := FHeader.OrigZone;
  Result.Net   := FHeader.OrigNet;
  Result.Node  := FHeader.OrigNode;
  Result.Point := FHeader.OrigPoint;
end;

function TPacketReader.GetDestAddr: TFidoAddr;
begin
  Result.Zone  := FHeader.DestZone;
  Result.Net   := FHeader.DestNet;
  Result.Node  := FHeader.DestNode;
  Result.Point := FHeader.DestPoint;
end;

{ ---------- TBundleManager ---------- }

constructor TBundleManager.Create(const ACfg: TMailerConfig);
begin
  inherited Create;
  FConfig := ACfg;
end;

function TBundleManager.BundleExt(Flavor: AnsiChar): string;
begin
  case UpCase(Flavor) of
    'C': Result := 'CUT';
    'D': Result := 'DUT';
    'H': Result := 'HUT';
    'O': Result := 'OUT';
  else
    Result := 'OUT';
  end;
end;

function TBundleManager.BundlePath(const Dest: TFidoAddr;
  Flavor: AnsiChar): string;
var
  ZoneDir, NodeDir: string;
begin
  { standard FrontDoor / BinkleyTerm outbound layout }
  { zone 1 = base outbound; other zones = outbound.NNN }
  if Dest.Zone = FConfig.Address.Zone then
    ZoneDir := IncludeTrailingPathDelimiter(FConfig.OutboundDir)
  else
    ZoneDir := IncludeTrailingPathDelimiter(FConfig.OutboundDir) +
               Format('%.3x', [Dest.Zone]) +
               PathDelim;
  ForceDirectories(ZoneDir);
  NodeDir := ZoneDir + Format('%.4x%.4x.%s',
    [Dest.Net, Dest.Node, BundleExt(Flavor)]);
  if Dest.Point <> 0 then
    NodeDir := ZoneDir + Format('%.4x%.4x.pnt' + PathDelim +
      '%.8x.%s',
      [Dest.Net, Dest.Node, Dest.Point, BundleExt(Flavor)]);
  Result := NodeDir;
end;

procedure TBundleManager.GetOutboundFiles(const Dest: TFidoAddr;
  List: TStringList);
var
  ZoneDir, Pattern: string;
  SR: TSearchRec;
  Flavors: string;
  I: Integer;
begin
  if Dest.Zone = FConfig.Address.Zone then
    ZoneDir := IncludeTrailingPathDelimiter(FConfig.OutboundDir)
  else
    ZoneDir := IncludeTrailingPathDelimiter(FConfig.OutboundDir) +
               Format('%.3x', [Dest.Zone]) + PathDelim;
  Flavors := 'CDHO';
  for I := 1 to 4 do begin
    Pattern := ZoneDir + Format('%.4x%.4x.*',
      [Dest.Net, Dest.Node]);
    if FindFirst(Pattern, faAnyFile, SR) = 0 then begin
      repeat
        List.Add(ZoneDir + SR.Name);
      until FindNext(SR) <> 0;
      FindClose(SR);
    end;
  end;
end;

function TBundleManager.OpenOutPkt(const Dest: TFidoAddr;
  Flavor: AnsiChar; const Password: string): TPacketWriter;
var
  PktFile: string;
begin
  PktFile := IncludeTrailingPathDelimiter(FConfig.TempDir) +
    Format('%.8x.pkt', [LongWord(Now * 86400)]);
  Result := TPacketWriter.Create(PktFile, FConfig, Dest, Password);
end;

procedure TBundleManager.MarkSent(const AFile: string);
begin
  DeleteFile(AFile);
end;

procedure TBundleManager.StorePktBundle(const PktFile: string;
  const Dest: TFidoAddr; Flavor: AnsiChar);
var
  Dest_: string;

begin
  Dest_ := BundlePath(Dest, Flavor);
  if not RenameFile(PktFile, Dest_) then begin
    { if rename across volumes, copy+delete }
    with TFileStream.Create(PktFile, fmOpenRead) do
    try
      with TFileStream.Create(Dest_, fmCreate) do
      try
        CopyFrom(TFileStream(TObject(nil){ placeholder }), 0);
      finally
        Free;
      end;
    finally
      Free;
    end;
    DeleteFile(PktFile);
  end;
end;

end.
