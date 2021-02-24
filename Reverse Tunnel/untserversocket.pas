unit untserversocket;

{$mode objfpc}{$H+}

interface

uses
  Windows, WinSock, Classes, SysUtils, untClientHandler, untPacketSystem, untClientSocket, untPendingBuffer, untUtils;

type
  TServerSocket = class(TThread)
    public
      constructor Create(iPort: Integer);
    protected
      procedure Execute; override;
    private
      m_iPort: Integer;
      m_hServer: TSocket;
      m_wsaData: TWSAData;
      m_ClientHandler: TClientHandler;
      m_PacketSystem: TPacketSystem;
      m_PendingBuffer: TPendingBuffer;
      procedure OnDataReceived_Callback(ClientSocket: TClientSocket; arr_bBuffer: array of byte; iAmount: Integer);
      procedure OnClientDisconnect_Callback(ClientSocket: TClientSocket);
      procedure OnPacketBufferReceived_Callback(ClientSocket: TClientSocket; strBuffer: String);
      procedure OnBufferFinished_Callback(ClientSocket: TClientSocket; strBuffer: String);
  end;

implementation

procedure TServerSocket.OnDataReceived_Callback(ClientSocket: TClientSocket; arr_bBuffer: array of byte; iAmount: Integer);
begin
  m_PendingBuffer.AddBuffer(ClientSocket, ByteArrayToString(arr_bBuffer));
end;

procedure TServerSocket.OnPacketBufferReceived_Callback(ClientSocket: TClientSocket; strBuffer: String);
var
  bPacket: byte;
  strArguments: String;
  iBufferLength: Integer;
begin
  iBufferLength := Length(strBuffer);

  CopyMemory(@bPacket, @strBuffer[1], 1);
  SetLength(strArguments, iBufferLength - 1);
  CopyMemory(@strArguments[1], @strBuffer[2], iBufferLength - 1);

  if bPacket = $1 then
  begin
    MessageBox(0, PAnsiChar(strArguments), nil, 0);
  end;
end;

procedure TServerSocket.OnBufferFinished_Callback(ClientSocket: TClientSocket; strBuffer: String);
var
  arr_bBuffer, arr_bData: array of byte;
  iLength: Integer;
begin
  iLength := Length(strBuffer);
  SetLength(arr_bBuffer, iLength);
  CopyMemory(@arr_bBuffer[0], @strBuffer[1], iLength);

  SetLength(arr_bData, iLength - 1);
  CopyMemory(@arr_bData[0], @arr_bBuffer[1], iLength - 1);

  if arr_bBuffer[0] = $1 {Header} then
  begin
    m_PacketSystem.HandleHeader(ClientSocket, arr_bData, iLength - 1);
  end
  else if arr_bBuffer[0] = $2 {Block} then
  begin
    m_PacketSystem.HandleBlock(ClientSocket, arr_bData, iLength - 1);
  end;

  ZeroMemory(@arr_bData[0], sizeof(arr_bData));
  ZeroMemory(@arr_bBuffer[0], sizeof(arr_bBuffer));
end;

procedure TServerSocket.OnClientDisconnect_Callback(ClientSocket: TClientSocket);
begin
  m_PendingBuffer.Cleanup(ClientSocket);
end;

constructor TServerSocket.Create(iPort: Integer);
begin
  m_iPort := iPort;
  m_hServer := INVALID_SOCKET;
  m_ClientHandler := TClientHandler.Create;
  m_ClientHandler.OnDataReceived := @OnDataReceived_Callback;
  m_ClientHandler.OnClientDisconnect := @OnClientDisconnect_Callback;

  m_PacketSystem := TPacketSystem.Create;
  m_PacketSystem.OnReceivedPacketBuffer := @OnPacketBufferReceived_Callback;

  m_PendingBuffer := TPendingBuffer.Create;
  m_PendingBuffer.OnBufferFinished := @OnBufferFinished_Callback;
  inherited Create(False);
end;

procedure TServerSocket.Execute;
var
  serverAddress, clientAddress: TSockAddrIn;
  iSize: Integer;
  hClient: TSocket;
begin
  if WSAStartup($0202, m_wsaData) <> 0 then Exit;

  m_hServer := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if m_hServer = INVALID_SOCKET then Exit;

  ZeroMemory(@serverAddress, sizeof(TSockAddrIn));
  serverAddress.sin_family := AF_INET;
  serverAddress.sin_addr.S_addr := INADDR_ANY;
  serverAddress.sin_port := htons(m_iPort);

  if bind(m_hServer, serverAddress, sizeof(serverAddress)) = 0 then
  begin
    listen(m_hServer, 100);
    while true do
    begin
      iSize := sizeof(TSockAddrIn);
      hClient := accept(m_hServer, @clientAddress, @iSize);

      if hClient <> INVALID_SOCKET then
      begin
        m_ClientHandler.AddClient(TClientSocket.Create(hClient, clientAddress));
      end;
    end;
  end;
end;

end.

