#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
# Trust necessary certificates in the container. This is maybe not the best way to do it. Mounting the files may be better.
COPY ["Application/Certificates/intermediate-certificate-1.crt", "/usr/local/share/ca-certificates/intermediate-certificate-1.crt"]
RUN chmod 644 /usr/local/share/ca-certificates/intermediate-certificate-1.crt && update-ca-certificates
COPY ["Application/Certificates/intermediate-certificate-2.crt", "/usr/local/share/ca-certificates/intermediate-certificate-2.crt"]
RUN chmod 644 /usr/local/share/ca-certificates/intermediate-certificate-2.crt && update-ca-certificates
COPY ["Application/Certificates/intermediate-certificate-3.crt", "/usr/local/share/ca-certificates/intermediate-certificate-3.crt"]
RUN chmod 644 /usr/local/share/ca-certificates/intermediate-certificate-3.crt && update-ca-certificates
COPY ["Application/Certificates/intermediate-certificate-4.crt", "/usr/local/share/ca-certificates/intermediate-certificate-4.crt"]
RUN chmod 644 /usr/local/share/ca-certificates/intermediate-certificate-4.crt && update-ca-certificates
COPY ["Application/Certificates/root-certificate.crt", "/usr/local/share/ca-certificates/root-certificate.crt"]
RUN chmod 644 /usr/local/share/ca-certificates/root-certificate.crt && update-ca-certificates
WORKDIR /app
#EXPOSE 80
#EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["Application/Application.csproj", "Application/"]
RUN dotnet restore "Application/Application.csproj"
COPY . .
WORKDIR "/src/Application"
RUN dotnet build "Application.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Application.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Application.dll"]