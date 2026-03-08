{ ==========================================================================
  FidoNodelist.pas — Nodelist parser and lookup
  Parses NODELIST.nnn / NODELIST.idx (V7 index optional)
  Falls back to sequential scan for small nodelists
  ========================================================================== }
unit FidoNodelist;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes, FidoNet;

type
  TNodelistEntry = record
    Addr     : TFidoAddr;
    Name     : string;
    Location : string;
    SysOp    : string;
    Phone    : string;
    BaudRate : LongWord;
    Flags    : string;
    Password : string;
    IsHub    : Boolean;
    IsHost   : Boolean;
    IsPvt    : Boolean;
    IsDown   : Boolean;
    IsHold   : Boolean;
  end;

  TNodelistIndex = class
  private
    FEntries : array of record
      Net, Node: Word;
      FileOfs:   LongWord;
    end;
    FCount : Integer;
  public
    procedure Clear;
    procedure Add(Net, Node: Word; Ofs: LongWord);
    function  Find(Net, Node: Word; var Ofs: LongWord): Boolean;
    procedure SortEntries;
  end;

  TNodelist = class
  private
    FFilename  : string;
    FIndex     : TNodelistIndex;
    FZone      : Word;
    FNet       : Word;

    procedure BuildIndex;
    function  ParseLine(const Line: string;
      var E: TNodelistEntry): Boolean;
    procedure ApplyFlags(var E: TNodelistEntry;
      const FlagsStr: string);
  public
    constructor Create(const AFilename: string);
    destructor  Destroy; override;
    function    Lookup(const Addr: TFidoAddr;
      var E: TNodelistEntry): Boolean;
    function    LookupNet(Net: Word; var E: TNodelistEntry): Boolean;
  end;

  { Multi-zone nodelist manager }
  TNodelistManager = class
  private
    FLists   : TList;
    FDir     : string;
  public
    constructor Create(const ADir: string);
    destructor  Destroy; override;
    procedure   LoadAll;
    function    Lookup(const Addr: TFidoAddr;
      var E: TNodelistEntry): Boolean;
  end;

implementation

{ ---------- TNodelistIndex ---------- }

procedure TNodelistIndex.Clear;
begin
  FCount := 0;
  SetLength(FEntries, 0);
end;

procedure TNodelistIndex.Add(Net, Node: Word; Ofs: LongWord);
begin
  if FCount >= Length(FEntries) then
    SetLength(FEntries, Max(64, Length(FEntries) * 2));
  FEntries[FCount].Net     := Net;
  FEntries[FCount].Node    := Node;
  FEntries[FCount].FileOfs := Ofs;
  Inc(FCount);
end;

function TNodelistIndex.Find(Net, Node: Word;
  var Ofs: LongWord): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to FCount-1 do
    if (FEntries[I].Net = Net) and (FEntries[I].Node = Node) then
    begin
      Ofs := FEntries[I].FileOfs;
      Result := True;
      Exit;
    end;
end;

procedure TNodelistIndex.SortEntries;
{ Simple insertion sort — index is small (<10000 entries typically) }
var
  I, J: Integer;
  Key: record Net, Node: Word; FileOfs: LongWord; end;
begin
  for I := 1 to FCount-1 do
  begin
    Key := FEntries[I];
    J := I-1;
    while (J >= 0) and
      ((FEntries[J].Net > Key.Net) or
       ((FEntries[J].Net = Key.Net) and
        (FEntries[J].Node > Key.Node))) do
    begin
      FEntries[J+1] := FEntries[J];
      Dec(J);
    end;
    FEntries[J+1] := Key;
  end;
end;

{ ---------- TNodelist ---------- }

constructor TNodelist.Create(const AFilename: string);
begin
  inherited Create;
  FFilename := AFilename;
  FIndex    := TNodelistIndex.Create;
  FZone     := 0;
  FNet      := 0;
  if FileExists(AFilename) then
    BuildIndex;
end;

destructor TNodelist.Destroy;
begin
  FIndex.Free;
  inherited;
end;

procedure TNodelist.ApplyFlags(var E: TNodelistEntry;
  const FlagsStr: string);
var
  Flags: TStringList;
  I: Integer;
  F: string;
begin
  Flags := TStringList.Create;
  try
    Flags.Delimiter := ',';
    Flags.DelimitedText := FlagsStr;
    for I := 0 to Flags.Count-1 do
    begin
      F := UpperCase(Flags[I]);
      if F = 'PVT'  then E.IsPvt  := True;
      if F = 'DOWN' then E.IsDown := True;
      if F = 'HOLD' then E.IsHold := True;
      if Copy(F,1,4) = 'PWD,' then
        E.Password := Copy(Flags[I],5,999);
    end;
  finally
    Flags.Free;
  end;
end;

function TNodelist.ParseLine(const Line: string;
  var E: TNodelistEntry): Boolean;
{ Nodelist line format:
    keyword,node,name,location,sysop,phone,baud,flags...
  keyword: Zone/Region/Host/Hub/Pvt/Node/Hold/Down/Boss/-
  Continuation lines (no comma at start) are comments or ;comments }
var
  Fields: TStringList;
  Keyword: string;
  NodeNum: Integer;
begin
  Result := False;
  FillChar(E, SizeOf(E), 0);
  if Length(Line) = 0 then Exit;
  if Line[1] = ';' then Exit;   { comment }
  Fields := TStringList.Create;
  try
    Fields.Delimiter := ',';
    Fields.StrictDelimiter := True;
    Fields.DelimitedText := Line;
    if Fields.Count < 6 then Exit;
    Keyword := UpperCase(Fields[0]);
    NodeNum := StrToIntDef(Fields[1], -1);
    if NodeNum < 0 then Exit;

    if Keyword = 'ZONE' then
    begin
      FZone := NodeNum;
      FNet  := NodeNum;
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := 0;
      E.IsHost := True;
    end
    else if Keyword = 'REGION' then
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := NodeNum;
      E.Addr.Node  := 0;
      E.IsHost := True;
    end
    else if (Keyword = 'HOST') or (Keyword = '-') then
    begin
      FNet := NodeNum;
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := 0;
      E.IsHost := True;
    end
    else if Keyword = 'HUB' then
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := NodeNum;
      E.IsHub := True;
    end
    else if Keyword = 'PVT' then
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := NodeNum;
      E.IsPvt := True;
    end
    else if Keyword = 'HOLD' then
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := NodeNum;
      E.IsHold := True;
    end
    else if Keyword = 'DOWN' then
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := NodeNum;
      E.IsDown := True;
    end
    else  { NODE or anything else }
    begin
      E.Addr.Zone  := FZone;
      E.Addr.Net   := FNet;
      E.Addr.Node  := NodeNum;
    end;

    E.Name     := Fields[2];
    E.Location := Fields[3];
    E.SysOp    := Fields[4];
    E.Phone    := Fields[5];
    if Fields.Count > 6 then
      E.BaudRate := StrToIntDef(Fields[6], 0);
    if Fields.Count > 7 then
    begin
      var FlagParts := '';
      var FI: Integer;
      for FI := 7 to Fields.Count-1 do
      begin
        if FlagParts <> '' then FlagParts := FlagParts + ',';
        FlagParts := FlagParts + Fields[FI];
      end;
      E.Flags := FlagParts;
      ApplyFlags(E, FlagParts);
    end;
    Result := True;
  finally
    Fields.Free;
  end;
end;

procedure TNodelist.BuildIndex;
{ Build in-memory index: Net/Node -> file offset }
var
  F: TextFile;
  Line: string;
  Ofs: LongWord;
  E: TNodelistEntry;
  FS: TFileStream;
begin
  { Use file stream to get position as we read }
  FS := TFileStream.Create(FFilename,
    fmOpenRead or fmShareDenyWrite);
  try
    FIndex.Clear;
    Ofs := 0;
    var Buf: AnsiString;
    var BufPos, BufLen: Integer;
    SetLength(Buf, 65536);
    BufPos := 1; BufLen := 0;

    var LineStart := LongWord(0);
    var CurLine  := '';

    while True do
    begin
      if BufPos > BufLen then
      begin
        BufLen := FS.Read(Buf[1], 65536);
        BufPos := 1;
        if BufLen = 0 then Break;
      end;
      var C := Buf[BufPos];
      Inc(BufPos);
      if C = #10 then
      begin
        { got a complete line }
        if (Length(CurLine) > 0) and (CurLine[Length(CurLine)] = #13) then
          SetLength(CurLine, Length(CurLine)-1);
        if ParseLine(CurLine, E) then
          FIndex.Add(E.Addr.Net, E.Addr.Node, LineStart);
        Inc(Ofs);
        LineStart := Ofs;
        CurLine := '';
      end else
      begin
        CurLine := CurLine + C;
        Inc(Ofs);
      end;
    end;
  finally
    FS.Free;
  end;
  FIndex.SortEntries;
end;

function TNodelist.Lookup(const Addr: TFidoAddr;
  var E: TNodelistEntry): Boolean;
var
  Ofs: LongWord;
  F: TextFile;
  Line: string;
  FS: TFileStream;
  BufPos, BufLen: Integer;
  Buf: AnsiString;
  CurLine: string;
  CurOfs: LongWord;
begin
  Result := False;
  if not FileExists(FFilename) then Exit;
  if not FIndex.Find(Addr.Net, Addr.Node, Ofs) then Exit;
  FS := TFileStream.Create(FFilename,
    fmOpenRead or fmShareDenyWrite);
  try
    FS.Seek(Ofs, soBeginning);
    SetLength(Buf, 4096);
    BufLen := FS.Read(Buf[1], 4096);
    BufPos := 1;
    CurLine := '';
    while BufPos <= BufLen do
    begin
      if Buf[BufPos] = #10 then
      begin
        if (Length(CurLine) > 0) and
           (CurLine[Length(CurLine)] = #13) then
          SetLength(CurLine, Length(CurLine)-1);
        if ParseLine(CurLine, E) then
        begin
          if FidoAddrEqual(E.Addr, Addr) then
          begin
            Result := True;
            Break;
          end;
        end;
        CurLine := '';
      end else
        CurLine := CurLine + Buf[BufPos];
      Inc(BufPos);
    end;
  finally
    FS.Free;
  end;
end;

function TNodelist.LookupNet(Net: Word; var E: TNodelistEntry): Boolean;
var
  Dummy: TFidoAddr;
begin
  Dummy.Zone  := FZone;
  Dummy.Net   := Net;
  Dummy.Node  := 0;
  Dummy.Point := 0;
  Result := Lookup(Dummy, E);
end;

{ ---------- TNodelistManager ---------- }

constructor TNodelistManager.Create(const ADir: string);
begin
  inherited Create;
  FDir   := IncludeTrailingPathDelimiter(ADir);
  FLists := TList.Create;
end;

destructor TNodelistManager.Destroy;
var
  I: Integer;
begin
  for I := 0 to FLists.Count-1 do
    TNodelist(FLists[I]).Free;
  FLists.Free;
  inherited;
end;

procedure TNodelistManager.LoadAll;
{ Find newest NODELIST.nnn in dir }
var
  SR: TSearchRec;
  Best: string;
  BestDay: Integer;
  Day: Integer;
  NL: TNodelist;
begin
  Best := '';
  BestDay := -1;
  if FindFirst(FDir + 'NODELIST.*', faAnyFile, SR) = 0 then
  begin
    repeat
      Day := StrToIntDef(ExtractFileExt(SR.Name), -1);
      if Day > BestDay then
      begin
        BestDay := Day;
        Best := FDir + SR.Name;
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
  if Best <> '' then
  begin
    NL := TNodelist.Create(Best);
    FLists.Add(NL);
  end;
end;

function TNodelistManager.Lookup(const Addr: TFidoAddr;
  var E: TNodelistEntry): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to FLists.Count-1 do
    if TNodelist(FLists[I]).Lookup(Addr, E) then
    begin
      Result := True;
      Exit;
    end;
end;

end.
