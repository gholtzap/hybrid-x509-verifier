package gen;

import java.security.SecureRandom;
import java.util.Date;

/**
 * 결정성 유틸 (재현성 규율). 모든 키 생성·시각·serial은 여기서 고정값을 받는다.
 * now()/nanoTime() 금지 — 이 클래스 밖에서 시간·난수 원천을 쓰지 말 것.
 */
public final class Det {
    private Det(){}

    /** 고정 시각 상수 (UTC). corpus 전체 공통. */
    public static final Date NOT_BEFORE = new Date(1767225600000L); // 2026-01-01T00:00:00Z
    public static final Date NOT_AFTER  = new Date(1798761600000L); // 2027-01-01T00:00:00Z
    /** Stage 3 desync: EXPIRED 변형용 만료 시각(VALIDATION_TIME 이전 → 검증 시점에 만료). */
    public static final Date NOT_AFTER_PAST = new Date(1775001600000L); // 2026-04-01T00:00:00Z (검증 2026-06-21 이전)
    /** 폐지/검증 기준 시점(상태공간 desync 판정용). */
    public static final Date VALIDATION_TIME = new Date(1782000000000L); // 2026-06-21T00:00:00Z (유효기간 내)
    public static final Date OCSP_PRODUCED_AT = new Date(1781996400000L); // 2026-06-20T23:00:00Z
    public static final Date OCSP_THIS_UPDATE = new Date(1781913600000L); // 2026-06-20T00:00:00Z
    public static final Date OCSP_NEXT_UPDATE = new Date(1782086400000L); // 2026-06-22T00:00:00Z
    public static final Date OCSP_STALE_THIS_UPDATE = new Date(1781654400000L); // 2026-06-17T00:00:00Z
    public static final Date OCSP_STALE_NEXT_UPDATE = new Date(1781740800000L); // 2026-06-18T00:00:00Z
    public static final Date OCSP_REVOCATION_TIME = new Date(1781827200000L); // 2026-06-19T00:00:00Z
    public static final Date FUTURE_REVOCATION_TIME = new Date(1782086400000L); // 2026-06-22T00:00:00Z

    /**
     * 라벨별 결정적 SecureRandom. 같은 라벨 → 같은 바이트열.
     * SHA1PRNG를 고정 시드로 setSeed(라벨) 하여 재현 가능한 스트림 확보.
     * (BC 키생성기는 주입된 SecureRandom에서 시드를 뽑으므로 키가 결정적으로 재현됨.)
     */
    public static SecureRandom rng(String label) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            // SHA1PRNG: nextBytes() 첫 호출 전의 setSeed는 시드로 확정 사용(추가적). 고정 마스터+라벨 → 라벨별 재현.
            sr.setSeed("pqc-probe/corpus/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            sr.setSeed(label.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return sr;
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
