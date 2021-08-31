package uns.ac.rs.userauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import uns.ac.rs.userauth.domain.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

}

