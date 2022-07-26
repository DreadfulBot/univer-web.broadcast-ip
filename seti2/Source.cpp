#include <iostream>
#include <string>
#include <sstream>
#include <exception>
#include <locale.h>	
//#include <windows.h>

struct FourOctets {
	bool isValid;
	int octets[ 4 ];
};

class UserException {
public:
	UserException() {
		
	}
};

//��������� �������� ������ �� �������
FourOctets GetOctets( const std::string & textLine ) {
	// ������������ �������� ������
	std::string testLine( textLine );

	// ������� ��������� ������� 
	FourOctets answer;
	answer.isValid = false;
	for(int i=0; i<4; i++) {
		answer.octets[i] = -1;
	}

	// ���� ��������� ������ - �������
	for (int i=0; i < testLine.length(); i++) {
		if (isalpha((unsigned char)testLine[i])) {
				return answer;
		}
	}

	// ��������� �� ������
	size_t foundOffset = 0;
	size_t numberOfDots = 0;
	while ( ( foundOffset = testLine.find( '.' ) ) != std::string::npos ) { 
		testLine.replace( foundOffset, 1, 1, ' ' );
		numberOfDots++;
	}

	// ��������� �� �������
	if( numberOfDots == 3 ) {
		std::stringstream ss( testLine );
		ss.exceptions( std::ios::failbit | std::ios::badbit );
		int *octets = answer.octets;
		try {
			ss >> octets[ 0 ] >> octets[ 1 ] >> octets[ 2 ] >> octets[ 3 ];
			for(int i=0; i<4; i++) {
				if(octets[i] > 255 || octets[i] < 0) {
					throw UserException();
				}
			}
			answer.isValid = true;
		} catch (...) {
			answer.isValid = false;
		}
	}
	return answer;
}

// ��������� ip-a���� �� ������� ������
FourOctets GetIpAddress(std::string ip) {
	FourOctets ipAddress = GetOctets(ip);
	return ipAddress;
}

// ��������� ����� �� ������� ������
FourOctets GetMask(std::string mask) {
	int posValues[] = {0, 128, 192, 224, 240, 248, 252, 254, 255};
	int posValuesCounter = 9;
	bool flag = false;
	int counter = 0;

	// ������� �����
	FourOctets ipMask = GetOctets(mask);
	if(ipMask.isValid = false) {
		return ipMask;
	}

	// ������ ����� ����� - ������� => ��� ����� �������
	if(ipMask.octets[0] == 0) {
		if(ipMask.octets[1] !=0 || ipMask.octets[2] !=0 || ipMask.octets[3] !=0) {
			ipMask.isValid = false;
			return ipMask;
		}
	}

	// ���������, ��� ������ ����� ����� ��������� ��������� ��������
	for(int i=0; i<4; i++) {
		for (int j=0; j<posValuesCounter; j++) {
			if (ipMask.octets[i] == posValues[j]) {
				counter++;
				break;
			}
		}
	}
	if (counter == 4) {
			ipMask.isValid = true;
	} else {
			ipMask.isValid = false;
			return ipMask;
	}

	try {
		for (int i=0; i<3; i++) {

			// ������ ��������� ����� ������� �� ���������
			if(ipMask.octets[i+1] != 0) {
				if(ipMask.octets[i] == 0) {
					throw UserException();
				}
			}

			// ���������� ����� ������� ������������ ����� 255
			if(ipMask.octets[i+1] > ipMask.octets[i]) {
				if(ipMask.octets[i] != 255) {
					throw UserException();
				}
			}

			// ������ ����������� �� ������ �����������
			if(ipMask.octets[i+1] > ipMask.octets[i]) {
				throw UserException();
			}

			// ���� ��� ����� ������
			ipMask.isValid = true;

		}
	} catch (...) {
		ipMask.isValid = false;
	}
	return ipMask;
}

// �������� �������� �����
FourOctets GetHostPart(FourOctets& address, FourOctets& mask) {
	FourOctets hostPart;
	for(int i=0; i<4; i++) {
		hostPart.octets[i] = address.octets[i] & (255 - mask.octets[i]);
	}
	return hostPart;
}

// �������� ������� �����
FourOctets GetWebPart(FourOctets& address, FourOctets& mask) {
	FourOctets webPart;
	for(int i=0; i<4; i++) {
		webPart.octets[i] = address.octets[i] & mask.octets[i];
	}
	return webPart;
}

// �������� ���� �� ���������
FourOctets GetDefaultGateway(FourOctets ipAddress, FourOctets ipMask) {
	FourOctets dg;
	dg = GetWebPart(ipAddress, ipMask);
	dg.octets[3] += 1;
	dg.isValid = true;
	return dg;
}

// �������� ����������������� �����
FourOctets GetBroadcastIp(FourOctets ipAddress, FourOctets ipMask) {
	FourOctets bcIp;
	size_t temp = 0;
	for (int i=0; i<4; i++) {
		bcIp.octets[i] = ipAddress.octets[i] | (255 - ipMask.octets[i]);
	}
	return bcIp;
}

// �������� ������������� ���� �� ����� � ������
void ValidateWeb(FourOctets& address, FourOctets& mask) {
	int counter = 0;
	FourOctets tempBcIp;
	FourOctets hostPart;
	try {
		tempBcIp = GetBroadcastIp(address, mask);

		// ip != ������������������
		for(int i=0; i<4; i++) {
			if(address.octets[i] == tempBcIp.octets[i]) {
				counter++;
			}
		}
		if(counter == 4) {
			throw UserException();
		}
		counter = 0;

		// �������� ����� != 0
		hostPart = GetHostPart(address, mask);
		for(int i=0; i<4; i++) {
			if(hostPart.octets[i] == 0) {
				counter++;
			}
		}
		if (counter == 4) {
			throw UserException();
		}
		counter = 0;

		// ���� ��� ����� ������
		mask.isValid = true;
		address.isValid = true;

	} catch (...) {
		mask.isValid = false;
		address.isValid = false;
	}

	// �������� ����� != ������������������
	/*FourOctets hostPart = GetHostPart(address, mask);
	for(int i=0; i<4; i++) {
		if(hostPart.octets[i] == tempBcIp.octets[i]) {
			counter++;
		}
	}
	if (counter == 4) {
		address.isValid = false;
		mask.isValid = false;
		return;
	} else {
		address.isValid = true;
		mask.isValid = true;
	}
	counter = 0;*/
	
	// ������� ����� != ip ������
	/*FourOctets webPart = GetWebPart(address, mask);
	for(int i=0; i<4; i++) {
		if(webPart.octets[i] == tempBcIp.octets[i]) {
			counter++;
		}
	}
	if (counter == 4) {
		address.isValid = false;
		mask.isValid = false;
		return;
	} else {
		address.isValid = true;
		mask.isValid = true;
	}
	counter = 0;*/
	return;
}


// ����� ������� ������ �� 2ip - ������ �� �������, ��� �� ��� �������� ���������, 
// ����� �������� �������������� ��������� �����
bool SplitStrToIpAndMask(std::string src, FourOctets& ipAddress, FourOctets& ipMask) {

	// ������� ������� �� ������� ������
	size_t targetSpaceOffset = 0;
	size_t curSpaceOffset = 0;
	size_t numOfSpaces = 0;

	while ( (curSpaceOffset = src.find( ' ' )) != std::string::npos ) {
			if (curSpaceOffset != std::string::npos) {
				targetSpaceOffset = curSpaceOffset;
			}
			src.replace(curSpaceOffset, 1, 1, '_');
			numOfSpaces++;
	}

	// ��������� �� ���-�� ��������
	if (numOfSpaces != 1) {
			ipAddress.isValid = false;
			ipMask.isValid = false;
			return false;
	} else {
		// ��������� ip-�����
		ipAddress = GetIpAddress(src.substr(0, targetSpaceOffset));

		// ��������� �����
		if(ipAddress.isValid = true) {
			ipMask = GetMask(src.substr(targetSpaceOffset+=1, src.length()));
		} else {
			return false;
		}

		// ��������� ���� �� ����� � ������
		if(ipAddress.isValid && ipMask.isValid) {
			ValidateWeb(ipAddress, ipMask);
		}
		return ipAddress.isValid && ipMask.isValid;
	}
}

// ������� ������ ip-������ ����� �����
void PrintAddress(FourOctets address) {
	for (int i=0; i<4; i++) {
		std::cout << address.octets[i];
		if (i != 3) {
			std::cout << ".";
		}
		if (i == 3) {
			std::cout << std::endl;
		}
	}
}

int main(void) {
	setlocale(LC_ALL, "RU");
	std::string inputString;
	FourOctets ipAddress;
	FourOctets ipMask;
	FourOctets bcIp;
	FourOctets dg;
	while( getline (std::cin, inputString) ) {
		// ��������� ������ �� ������� �� 2 �����. ���� ������ ������ - �����.
		SplitStrToIpAndMask(inputString, ipAddress, ipMask);
		try {
			if( !ipAddress.isValid || !ipMask.isValid) {
				throw UserException();
			}
			// �������� ����������������� ����� �� ������ � �����
			bcIp = GetBroadcastIp(ipAddress, ipMask);
			// dg = GetDefaultGateway(ipAddress, ipMask);
			if( !dg.isValid) {
				throw UserException();
			} else {
				// ���� ��� ������ - �������� ����������������� �����
				PrintAddress(dg);
			}
		} catch (UserException) {
			std::cout << "X" << std::endl;
		}
	}
	return 0;
}