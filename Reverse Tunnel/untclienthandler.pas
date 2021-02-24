unit untclienthandler;

{$mode objfpc}{$H+}

interface

uses
  Windows, Winsock, Classes, SysUtils, untClientSocket;

type
  TOnDataReceived = procedure(ClientSocket: TClientSocket; arr_bBuffer: array of byte; iAmount: Integer) of object;
  TOnClientDisconnect = procedure(ClientSocket: TClientSocket) of object;

  TClientHandler = class(TThread)
    private
      m_Clients: array of TClientSocket;
      m_fset: TFDSET;
      m_CriticalSection: TRTLCriticalSection;
      FOnDataReceived: TOnDataReceived;
      FOnClientDisconnect: TOnClientDisconnect;
    public
      constructor Create;
      procedure AddClient(ClientSocket: TClientSocket);
      procedure RemoveClient(ClientSocket: TClientSocket);
      function GetClientCount: Integer;
      property OnDataReceived: TOnDataReceived read FOnDataReceived write FOnDataReceived;
      property OnClientDisconnect: TOnClientDisconnect read FOnClientDisconnect write FOnClientDisconnect;
    protected
      procedure Execute;override;
  end;

implementation

constructor TClientHandler.Create;
begin
  InitCriticalSection(m_CriticalSection);
  inherited Create(False);
end;

procedure TClientHandler.Execute;
var
  iClientIndex, iClientCount, iDataRead: Integer;
  arr_bBuffer: array[0..4095] of Byte;
  fixedBuffer: array of byte;
begin
  while not Self.Terminated do
  begin
    while GetClientCount = 0 do Sleep(100);

    iClientCount := GetClientCount;

    FD_ZERO(m_fset);

    for iClientIndex := 0 to iClientCount - 1 do
    begin
      if m_Clients[iClientIndex].GetSocket = INVALID_SOCKET then continue;

      FD_SET(m_Clients[iClientIndex].GetSocket, m_fset);
    end;

    if select(0, @m_fset, nil, nil, nil) <> SOCKET_ERROR then
    begin
      for iClientIndex := 0 to iClientCount - 1 do
      begin
        if m_Clients[iClientIndex].GetSocket = INVALID_SOCKET then continue;

        if FD_ISSET(m_Clients[iClientIndex].GetSocket, m_fset) then
        begin
          ZeroMemory(@arr_bBuffer, sizeof(arr_bBuffer));

          if recv(m_Clients[iClientIndex].GetSocket, arr_bBuffer, sizeof(arr_bBuffer), 0) > 0 then
          begin
            asm
               mov iDataRead, eax
            end;

            SetLength(fixedBuffer, iDataRead);
            CopyMemory(@fixedBuffer[0], @arr_bBuffer[0], iDataRead);

            if Assigned(FOnDataReceived) then
            begin
              FOnDataReceived(m_Clients[iClientIndex], fixedBuffer, iDataRead);
            end;

            ZeroMemory(@fixedBuffer[0], iDataRead);
            ZeroMemory(@arr_bBuffer[0], sizeof(arr_bBuffer));
          end else
          begin
            if Assigned(FOnClientDisconnect) then
            begin
              FOnClientDisconnect(m_Clients[iClientIndex]);
            end;
            RemoveClient(m_Clients[iClientIndex]);
          end;
        end;
      end;
    end;
  end;
end;

procedure TClientHandler.AddClient(ClientSocket: TClientSocket);
var
  iArrayLength, i: Integer;
  bAdded: Boolean;
begin
  EnterCriticalSection(m_CriticalSection);
  bAdded := False;

  try
    iArrayLength := Length(m_Clients);

    for i := 0 to iArrayLength - 1 do
    begin
      if(m_Clients[i].GetSocket = INVALID_SOCKET) then
      begin
        m_Clients[i] := ClientSocket;
        bAdded := True;
      end;
    end;

    if not bAdded then
    begin
      SetLength(m_Clients, iArrayLength + 1);
      m_Clients[iArrayLength] := ClientSocket;
    end;
  finally
    LeaveCriticalSection(m_CriticalSection);
  end;
end;

procedure TClientHandler.RemoveClient(ClientSocket: TClientSocket);
var
  iClientCount, i, iNewClientCount: Integer;
begin
  iClientCount := GetClientCount;

  iNewClientCount := iClientCount;

  for i := 0 to iClientCount - 1 do
  begin
    if m_Clients[i] = ClientSocket then
    begin
      m_Clients[i].Disconnect;
      break;
    end;
  end;

  while (iNewClientCount > 0) and (m_Clients[iNewClientCount - 1].GetSocket = INVALID_SOCKET) do iNewClientCount -= 1;

  if iNewClientCount <> iClientCount then
  begin
    SetLength(m_Clients, iNewClientCount);
  end;
end;

function TClientHandler.GetClientCount: Integer;
begin
  EnterCriticalSection(m_CriticalSection);
  Result := Length(m_Clients);
  LeaveCriticalSection(m_CriticalSection);
end;

end.

