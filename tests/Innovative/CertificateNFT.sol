// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract CertificateNFT is ERC721, Ownable {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;

    struct Cert {
        string studentName;
        string courseName;
        string metadata; // Stores additional information (e.g., grades, honors)
        uint issueDate;
        uint expiryDate;
        bool valid;
    }

    mapping(uint => Cert) public certificates; // Mapping of token ID to certificate
    mapping(address => bool) public authorizedIssuers; // Institutions authorized to issue certificates
    mapping(uint => string) public revocationReason; // Reason for revocation

    event CertificateIssued(uint tokenId, address recipient, string studentName, string courseName, uint issueDate, uint expiryDate);
    event CertificateRevoked(uint tokenId, string reason);

    // Constructor: Passes the name and symbol to the ERC721 constructor and msg.sender to the Ownable constructor
    constructor() ERC721("CertificationNFT", "CERTNFT") Ownable(msg.sender) {}

    modifier onlyAuthorized() {
        require(authorizedIssuers[msg.sender], "Not authorized to issue certificates");
        _;
    }

    // Function to authorize institutions to issue certificates
    function addAuthorizedIssuer(address _issuer) public onlyOwner {
        authorizedIssuers[_issuer] = true;
    }

    // Function to issue a certificate as an NFT
    function issueCertificate(
        address recipient,
        string memory studentName,
        string memory courseName,
        string memory metadata,
        uint expiryDate
    ) public onlyAuthorized returns (uint) {
        _tokenIds.increment();
        uint newCertId = _tokenIds.current();

        certificates[newCertId] = Cert({
            studentName: studentName,
            courseName: courseName,
            metadata: metadata,
            issueDate: block.timestamp,
            expiryDate: expiryDate,
            valid: true
        });

        _mint(recipient, newCertId);
        emit CertificateIssued(newCertId, recipient, studentName, courseName, block.timestamp, expiryDate);

        return newCertId;
    }

    // Function to verify certificate validity and details
    function verifyCertificate(uint certId) public view returns (string memory, string memory, string memory, uint, uint, bool) {
        Cert memory cert = certificates[certId];
        return (cert.studentName, cert.courseName, cert.metadata, cert.issueDate, cert.expiryDate, cert.valid);
    }

    // Function to revoke a certificate with a reason
    function revokeCertificate(uint certId, string memory reason) public onlyAuthorized {
        require(certificates[certId].valid, "Certificate already revoked");
        certificates[certId].valid = false;
        revocationReason[certId] = reason;

        emit CertificateRevoked(certId, reason);
    }

    // Function to check if a certificate is expired
    function isExpired(uint certId) public view returns (bool) {
        return (block.timestamp > certificates[certId].expiryDate);
    }

    // Function to get the reason for revocation
    function getRevocationReason(uint certId) public view returns (string memory) {
        require(!certificates[certId].valid, "Certificate is valid");
        return revocationReason[certId];
    }

    // Analytics: Get total number of issued certificates
    function totalIssuedCertificates() public view returns (uint) {
        return _tokenIds.current();
    }

    // Analytics: Get total number of valid certificates
    function validCertificates() public view returns (uint) {
        uint validCount = 0;
        for (uint i = 1; i <= _tokenIds.current(); i++) {
            if (certificates[i].valid && !isExpired(i)) {
                validCount++;
            }
        }
        return validCount;
    }

    // Analytics: Get total number of revoked certificates
    function revokedCertificates() public view returns (uint) {
        uint revokedCount = 0;
        for (uint i = 1; i <= _tokenIds.current(); i++) {
            if (!certificates[i].valid) {
                revokedCount++;
            }
        }
        return revokedCount;
    }
}
