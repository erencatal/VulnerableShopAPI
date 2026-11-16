# 1. Build stage: Compiles the C# source code using .NET 10 SDK
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["VulnerableShopAPI.csproj", "./"]
RUN dotnet restore "VulnerableShopAPI.csproj"
COPY . .
RUN dotnet publish "VulnerableShopAPI.csproj" -c Release -o /app/publish

# 2. Runtime stage: Runs the compiled web API on port 8080
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "VulnerableShopAPI.dll"]