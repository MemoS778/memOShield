#!/bin/bash
# memOShield Docker Quick Test
# Docker ile memOShield'ün test edilmesi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  memOShield Docker Test${NC}"
echo -e "${BLUE}========================================${NC}\n"

# 1. Docker kontrolü
echo -e "${YELLOW}[1/4] Checking Docker...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# 2. Image oluştur
echo -e "\n${YELLOW}[2/4] Building Docker image...${NC}"
if docker build -t memoshield:test . > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker image built${NC}"
else
    echo -e "${RED}✗ Docker build failed${NC}"
    exit 1
fi

# 3. Container çalıştır
echo -e "\n${YELLOW}[3/4] Starting container...${NC}"
CONTAINER_ID=$(docker run -d -p 5000:5000 -e ADMIN_PASSWORD=testpass memoshield:test)
if [ -z "$CONTAINER_ID" ]; then
    echo -e "${RED}✗ Container start failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Container started (ID: ${CONTAINER_ID:0:12})${NC}"

# 4. Container testi
echo -e "\n${YELLOW}[4/4] Testing container...${NC}"
sleep 3

# Flask testi
if docker exec $CONTAINER_ID curl -s http://127.0.0.1:5000/ > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Flask app responding${NC}"
else
    echo -e "${RED}✗ Flask app not responding${NC}"
    docker stop $CONTAINER_ID > /dev/null
    exit 1
fi

# API testi
if docker exec $CONTAINER_ID curl -s http://127.0.0.1:5000/api/events > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API endpoints working${NC}"
else
    echo -e "${RED}✗ API endpoints failed${NC}"
    docker stop $CONTAINER_ID > /dev/null
    exit 1
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}✓ All Docker tests passed!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Container Info:${NC}"
echo -e "ID:       ${BLUE}${CONTAINER_ID:0:12}${NC}"
echo -e "Web URL:  ${BLUE}http://127.0.0.1:5000${NC}"
echo -e "UI Demo:  ${BLUE}http://127.0.0.1:5000/demo${NC}"
echo -e "Admin:    ${BLUE}password: testpass${NC}"

echo -e "\n${YELLOW}Stop container:${NC}"
echo -e "  ${BLUE}docker stop $CONTAINER_ID${NC}"

echo -e "\n${YELLOW}View logs:${NC}"
echo -e "  ${BLUE}docker logs -f $CONTAINER_ID${NC}"
