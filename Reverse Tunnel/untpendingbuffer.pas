unit untPendingBuffer;

{$mode delphi}

interface

uses
  Windows, Winsock, Classes, SysUtils, untUtils, untClientSocket;

type
  TBuffer = packed record
    ClientSocket: TClientSocket;
    strBuffer: String;
  end;

  TOnBufferFinished = procedure(ClientSocket: TClientSocket; strBuffer: String) of object;

  TPendingBuffer = class
    private
      m_PendingBuffer: array of TBuffer;
      m_CriticalSection: TRTLCriticalSection;
      FOnBufferFinished: TOnBufferFinished;
      procedure ScanBuffer(ClientSocket: TClientSocket);
      function FindEmpty: Integer;
    public
      constructor Create;
      procedure AddBuffer(ClientSocket: TClientSocket; strBuffer: String);
      procedure Cleanup(ClientSocket: TClientSocket);
    property
      OnBufferFinished: TOnBufferFinished read FOnBufferFinished write FOnBufferFinished;
  end;

implementation

constructor TPendingBuffer.Create;
begin
  InitCriticalSection(m_CriticalSection);
end;

procedure TPendingBuffer.ScanBuffer(ClientSocket: TClientSocket);
var
  i, iIndex, iDelimPos: Integer;
  strData: String;
begin
  iIndex := Length(m_PendingBuffer);

  for i := 0 to iIndex - 1 do
  begin
    if m_PendingBuffer[i].ClientSocket = ClientSocket then
    begin
      while true do
      begin
        iDelimPos := Pos(';', m_PendingBuffer[i].strBuffer);

        if iDelimPos = 0 then break;

        strData := Copy(m_PendingBuffer[i].strBuffer, 1, iDelimPos - 1);
        Delete(m_PendingBuffer[i].strBuffer, 1, iDelimPos);

        if Assigned(FOnBufferFinished) then
        begin
          FOnBufferFinished(ClientSocket, strData);
        end;
      end;
    end;
  end;
end;

function TPendingBuffer.FindEmpty: Integer;
var
  i: Integer;
begin
  Result := -1;

  for i := 0 to Length(m_PendingBuffer) -1 do
  begin
    if m_PendingBuffer[i].ClientSocket = nil then
    begin
      Result := i;
      break;
    end;
  end;
end;

procedure TPendingBuffer.AddBuffer(ClientSocket: TClientSocket; strBuffer: String);
var
  i, iIndex, iEmptyIndex: Integer;
  bAdded: Boolean;
begin
  EnterCriticalSection(m_CriticalSection);

  bAdded := False;
  iIndex := Length(m_PendingBuffer);

  for i := 0 to iIndex - 1 do
  begin
    if m_PendingBuffer[i].ClientSocket = ClientSocket then
    begin
      m_PendingBuffer[i].strBuffer += strBuffer;
      bAdded := True;
      break;
    end;
  end;

  iEmptyIndex := FindEmpty;

    if not bAdded then
    begin
      if iEmptyIndex <> -1 then
      begin
        m_PendingBuffer[iEmptyIndex].ClientSocket := ClientSocket;
        m_PendingBuffer[iEmptyIndex].strBuffer := strBuffer;
      end else
      begin
        SetLength(m_PendingBuffer, iIndex + 1);
        m_PendingBuffer[iIndex].ClientSocket := ClientSocket;
        m_PendingBuffer[iIndex].strBuffer := strBuffer;
      end;
    end;

  ScanBuffer(ClientSocket);
  LeaveCriticalSection(m_CriticalSection);
end;

procedure TPendingBuffer.Cleanup(ClientSocket: TClientSocket);
var
  i, iIndex: Integer;
begin
  EnterCriticalSection(m_CriticalSection);

  iIndex := Length(m_PendingBuffer);

  for i := 0 to iIndex - 1 do
  begin
    if m_PendingBuffer[i].ClientSocket = ClientSocket then
    begin
      ZeroMemory(@m_PendingBuffer[i], sizeof(TBuffer));
    end;
  end;
  LeaveCriticalSection(m_CriticalSection);
end;

end.

