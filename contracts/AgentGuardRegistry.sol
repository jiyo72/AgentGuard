// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @dev Minimal read-only interface for the official SPACE ID Agent ID
///      registry (ERC-721, non-transferable). Only `balanceOf` is ever used,
///      and it is used exclusively as a view call (STATICCALL).
interface IAgentIdRegistry {
    function balanceOf(address owner) external view returns (uint256);
}

/// @title AgentGuardRegistry
/// @notice On-chain safety-verdict registry for AI agents.
///
///         Auditors who hold an Agent ID post safety verdicts about target
///         contracts (SAFE / CAUTION / DANGER, a 0-100 score, and a hash +
///         URI of an off-chain audit report). Any agent or contract can call
///         `check(target)` before interacting with an unknown contract and
///         get an aggregate, deterministic consensus — a pre-flight safety
///         check that is composable on-chain.
///
/// @dev    SECURITY POSTURE (by construction, not by add-ons):
///         - IMMUTABLE and OWNERLESS: no owner, no admin, no proxy, no
///           upgrade path, no pause, no setters of any kind after deployment.
///           The Agent ID registry address is fixed at construction in an
///           `immutable` variable and can never change.
///         - HOLDS NO FUNDS: there are no payable functions and no
///           receive/fallback, so plain value transfers revert. The contract
///           never reads or relies on its own balance.
///         - ONE EXTERNAL CALL ONLY: a read-only `balanceOf` STATICCALL to
///           the immutable Agent ID registry address, executed BEFORE any
///           state change. Because the call is a STATICCALL, the callee
///           cannot modify state, and any reentrant call into this contract
///           from inside that frame would itself be inside a static context
///           and revert the moment it tried to write. Reentrancy is
///           therefore impossible by construction, so no reentrancy guard
///           is used (it would only add gas, not safety).
///         - FAIL CLOSED: if the Agent ID registry call reverts or returns
///           malformed data, or the caller holds no Agent ID, every write
///           reverts. There is no path that writes without a successful
///           positive balance check.
///         - CHECKS-EFFECTS everywhere: all validation and the gate run
///           before any storage write; there are no external calls after
///           effects (there are no external calls besides the gate at all).
///         - No name-to-wallet lookup feature exists or can be added.
contract AgentGuardRegistry {
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// @notice Verdict status codes.
    uint8 public constant STATUS_SAFE = 1;
    uint8 public constant STATUS_CAUTION = 2;
    uint8 public constant STATUS_DANGER = 3;

    /// @notice Maximum byte length of a report / profile URI (bounds bloat).
    uint256 public constant MAX_URI_LENGTH = 200;

    /// @notice Minimum seconds between two verdict posts by the same auditor.
    uint256 public constant POST_COOLDOWN = 60;

    /// @notice Maximum page size returned by `listVerdicts`.
    uint256 public constant MAX_PAGE_SIZE = 100;

    // ------------------------------------------------------------------
    // Immutable configuration
    // ------------------------------------------------------------------

    /// @notice The Agent ID registry (ERC-721) used for the holder gate.
    ///         Fixed forever at construction; for production this is the
    ///         official SPACE ID Agent ID registry on BNB Chain:
    ///         0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F
    address public immutable AGENT_ID_REGISTRY;

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    error ZeroRegistry();
    error ZeroTarget();
    error NotAgentIdHolder();
    error InvalidStatus();
    error InvalidScore();
    error UriTooLong();
    error CooldownActive(uint256 retryAt);
    error NoVerdict();

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event VerdictPosted(
        address indexed target,
        address indexed auditor,
        uint8 status,
        uint8 score,
        bytes32 reportHash
    );
    event VerdictUpdated(
        address indexed target,
        address indexed auditor,
        uint8 status,
        uint8 score,
        bytes32 reportHash
    );
    event VerdictRevoked(address indexed target, address indexed auditor, uint8 previousStatus);
    event AgentRegistered(address indexed agent, string profileURI);

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    struct Verdict {
        uint8 status; // 1=SAFE, 2=CAUTION, 3=DANGER
        uint8 score; // 0..100
        bytes32 reportHash; // hash of the off-chain audit report
        string reportURI; // location of the off-chain audit report
        uint64 updatedAt; // last post/update timestamp
        bool exists;
    }

    struct Aggregate {
        uint32 safeCount;
        uint32 cautionCount;
        uint32 dangerCount;
        uint32 verdictCount;
        uint256 scoreSum; // sum of scores of all active verdicts
    }

    struct AuditorInfo {
        uint32 verdictCount; // number of active verdicts by this auditor
        bool registered;
        uint64 registeredAt;
        string profileURI;
    }

    /// @dev verdicts[target][auditor] — exactly one active verdict per pair.
    mapping(address => mapping(address => Verdict)) private _verdicts;

    /// @dev Incrementally maintained aggregates per target.
    mapping(address => Aggregate) private _aggregates;

    /// @dev Auditor list per target, for pagination.
    mapping(address => address[]) private _targetAuditors;

    /// @dev 1-based index of an auditor in `_targetAuditors[target]`
    ///      (0 means "not present"). Enables O(1) swap-and-pop removal.
    mapping(address => mapping(address => uint256)) private _auditorIndex;

    /// @dev Per-auditor profile + counters.
    mapping(address => AuditorInfo) private _auditors;

    /// @dev Last verdict-post timestamp per auditor (cooldown).
    mapping(address => uint256) private _lastPostAt;

    /// @notice Total number of registered agents.
    uint256 public totalRegisteredAgents;

    /// @notice Total number of active verdicts across all targets.
    uint256 public totalVerdicts;

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// @param agentIdRegistry Address of the Agent ID ERC-721 registry.
    ///        Stored immutably; there is no way to change it afterwards.
    constructor(address agentIdRegistry) {
        if (agentIdRegistry == address(0)) revert ZeroRegistry();
        AGENT_ID_REGISTRY = agentIdRegistry;
    }

    // NOTE: no receive() and no fallback() are defined on purpose.
    // Plain BNB transfers and calls to unknown functions revert, so this
    // contract can never accept or custody funds through normal calls.

    // ------------------------------------------------------------------
    // Gate
    // ------------------------------------------------------------------

    /// @dev Fails closed, deterministically, on EVERY failure mode: if the
    ///      registry call reverts, returns malformed/short/long data, or
    ///      reports a zero balance, the write reverts with NotAgentIdHolder.
    ///      This is the ONLY external call in the contract. It is an
    ///      explicit low-level STATICCALL (read-only) and runs before any
    ///      state change. A low-level call is used instead of an interface
    ///      try/catch because, under solc 0.8.26, a malformed-returndata
    ///      failure through the high-level path propagates as a bare
    ///      data-less revert; validating the return data by hand makes the
    ///      fail-closed behaviour identical for every failure mode.
    function _requireAgentId(address account) internal view {
        (bool ok, bytes memory data) = AGENT_ID_REGISTRY.staticcall(
            abi.encodeWithSelector(IAgentIdRegistry.balanceOf.selector, account)
        );
        if (!ok || data.length != 32) revert NotAgentIdHolder();
        uint256 balance = abi.decode(data, (uint256));
        if (balance == 0) revert NotAgentIdHolder();
    }

    // ------------------------------------------------------------------
    // Writes (all gated by Agent ID ownership of msg.sender)
    // ------------------------------------------------------------------

    /// @notice Post a safety verdict about `target`, or overwrite your own
    ///         previous verdict on the same target. One active verdict per
    ///         (auditor, target); aggregates are updated incrementally, so
    ///         an update never double-counts.
    /// @param target     Contract being judged (never the zero address).
    /// @param status     1=SAFE, 2=CAUTION, 3=DANGER.
    /// @param score      0..100 safety score.
    /// @param reportHash Hash of the off-chain audit report (may be zero
    ///                   if the auditor publishes no report).
    /// @param reportURI  Location of the audit report (max 200 bytes).
    function postVerdict(
        address target,
        uint8 status,
        uint8 score,
        bytes32 reportHash,
        string calldata reportURI
    ) external {
        // ---- checks ----
        if (target == address(0)) revert ZeroTarget();
        if (status < STATUS_SAFE || status > STATUS_DANGER) revert InvalidStatus();
        if (score > 100) revert InvalidScore();
        if (bytes(reportURI).length > MAX_URI_LENGTH) revert UriTooLong();
        _requireAgentId(msg.sender);
        uint256 last = _lastPostAt[msg.sender];
        if (block.timestamp < last + POST_COOLDOWN) {
            revert CooldownActive(last + POST_COOLDOWN);
        }

        // ---- effects ----
        _lastPostAt[msg.sender] = block.timestamp;

        Verdict storage v = _verdicts[target][msg.sender];
        Aggregate storage agg = _aggregates[target];
        if (v.exists) {
            _removeFromAggregate(agg, v.status, v.score);
            _addToAggregate(agg, status, score);
            v.status = status;
            v.score = score;
            v.reportHash = reportHash;
            v.reportURI = reportURI;
            v.updatedAt = uint64(block.timestamp);
            emit VerdictUpdated(target, msg.sender, status, score, reportHash);
        } else {
            _verdicts[target][msg.sender] = Verdict({
                status: status,
                score: score,
                reportHash: reportHash,
                reportURI: reportURI,
                updatedAt: uint64(block.timestamp),
                exists: true
            });
            _targetAuditors[target].push(msg.sender);
            _auditorIndex[target][msg.sender] = _targetAuditors[target].length; // 1-based
            _addToAggregate(agg, status, score);
            _auditors[msg.sender].verdictCount += 1;
            totalVerdicts += 1;
            emit VerdictPosted(target, msg.sender, status, score, reportHash);
        }
    }

    /// @notice Remove your own verdict on `target`. Nobody can remove or
    ///         modify another auditor's verdict.
    function revokeVerdict(address target) external {
        _requireAgentId(msg.sender);

        Verdict storage v = _verdicts[target][msg.sender];
        if (!v.exists) revert NoVerdict();
        uint8 previousStatus = v.status;

        Aggregate storage agg = _aggregates[target];
        _removeFromAggregate(agg, v.status, v.score);
        delete _verdicts[target][msg.sender];

        // O(1) swap-and-pop removal from the auditor list.
        address[] storage list = _targetAuditors[target];
        uint256 idx = _auditorIndex[target][msg.sender]; // 1-based
        address lastAuditor = list[list.length - 1];
        if (lastAuditor != msg.sender) {
            list[idx - 1] = lastAuditor;
            _auditorIndex[target][lastAuditor] = idx;
        }
        list.pop();
        delete _auditorIndex[target][msg.sender];

        _auditors[msg.sender].verdictCount -= 1;
        totalVerdicts -= 1;
        emit VerdictRevoked(target, msg.sender, previousStatus);
    }

    /// @notice Register (or update) your agent profile. One registration
    ///         per Agent ID address; only the holder of that address can
    ///         register or update it. This is the community interaction
    ///         surface of the registry.
    /// @param profileURI Location of the agent's profile (max 200 bytes).
    function registerAgent(string calldata profileURI) external {
        if (bytes(profileURI).length > MAX_URI_LENGTH) revert UriTooLong();
        _requireAgentId(msg.sender);

        AuditorInfo storage info = _auditors[msg.sender];
        if (!info.registered) {
            info.registered = true;
            info.registeredAt = uint64(block.timestamp);
            totalRegisteredAgents += 1;
        }
        info.profileURI = profileURI;
        emit AgentRegistered(msg.sender, profileURI);
    }

    // ------------------------------------------------------------------
    // Reads (all view, free, simple)
    // ------------------------------------------------------------------

    /// @notice Aggregate pre-flight check for a target contract.
    /// @dev    CONSENSUS RULE (deterministic):
    ///         - `consensusStatus` is the status with the highest number of
    ///           active verdicts. Ties are broken toward the MORE CAUTIOUS
    ///           status (DANGER beats CAUTION beats SAFE).
    ///         - `consensusScore` is the plain average of the scores of all
    ///           active verdicts (every auditor weighted equally), rounded
    ///           down. It is 0 when there are no verdicts.
    ///         - With no verdicts, all counts are 0 and consensusStatus is 0.
    /// @return safeCount       Active SAFE verdicts.
    /// @return cautionCount    Active CAUTION verdicts.
    /// @return dangerCount     Active DANGER verdicts.
    /// @return verdictCount    Total active verdicts.
    /// @return consensusScore  Average score (0 if none).
    /// @return consensusStatus 0=none, 1=SAFE, 2=CAUTION, 3=DANGER.
    function check(address target)
        external
        view
        returns (
            uint32 safeCount,
            uint32 cautionCount,
            uint32 dangerCount,
            uint32 verdictCount,
            uint256 consensusScore,
            uint8 consensusStatus
        )
    {
        Aggregate storage agg = _aggregates[target];
        safeCount = agg.safeCount;
        cautionCount = agg.cautionCount;
        dangerCount = agg.dangerCount;
        verdictCount = agg.verdictCount;
        consensusScore = verdictCount == 0 ? 0 : agg.scoreSum / verdictCount;

        // Highest count wins; iterating from most to least cautious and
        // replacing only on a STRICTLY greater count makes ties resolve
        // toward the more cautious status.
        uint32 best = 0;
        if (dangerCount > best) {
            best = dangerCount;
            consensusStatus = STATUS_DANGER;
        }
        if (cautionCount > best) {
            best = cautionCount;
            consensusStatus = STATUS_CAUTION;
        }
        if (safeCount > best) {
            consensusStatus = STATUS_SAFE;
        }
    }

    /// @notice Read one auditor's verdict on one target.
    /// @return exists     Whether the verdict exists.
    /// @return status     1=SAFE, 2=CAUTION, 3=DANGER (0 if none).
    /// @return score      0..100 (0 if none).
    /// @return reportHash Hash of the off-chain audit report.
    /// @return reportURI  Location of the audit report.
    /// @return updatedAt  Timestamp of the last post/update.
    function getVerdict(address target, address auditor)
        external
        view
        returns (
            bool exists,
            uint8 status,
            uint8 score,
            bytes32 reportHash,
            string memory reportURI,
            uint64 updatedAt
        )
    {
        Verdict storage v = _verdicts[target][auditor];
        return (v.exists, v.status, v.score, v.reportHash, v.reportURI, v.updatedAt);
    }

    /// @notice Number of auditors with an active verdict on `target`
    ///         (the total that `listVerdicts` paginates over).
    function targetAuditorCount(address target) external view returns (uint256) {
        return _targetAuditors[target].length;
    }

    struct VerdictView {
        address auditor;
        uint8 status;
        uint8 score;
        bytes32 reportHash;
        string reportURI;
        uint64 updatedAt;
    }

    /// @notice Paginated list of active verdicts on `target`.
    /// @dev    `limit` is clamped to MAX_PAGE_SIZE. An offset at or beyond
    ///         the end returns an empty array. Ordering is insertion order
    ///         and may change when a verdict is revoked (swap-and-pop).
    function listVerdicts(address target, uint256 offset, uint256 limit)
        external
        view
        returns (VerdictView[] memory page)
    {
        address[] storage list = _targetAuditors[target];
        uint256 total = list.length;
        if (offset >= total || limit == 0) {
            return new VerdictView[](0);
        }
        if (limit > MAX_PAGE_SIZE) limit = MAX_PAGE_SIZE;
        uint256 end = offset + limit;
        if (end > total) end = total;
        page = new VerdictView[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            address auditor = list[i];
            Verdict storage v = _verdicts[target][auditor];
            page[i - offset] = VerdictView({
                auditor: auditor,
                status: v.status,
                score: v.score,
                reportHash: v.reportHash,
                reportURI: v.reportURI,
                updatedAt: v.updatedAt
            });
        }
    }

    /// @notice Per-auditor statistics and registration state.
    /// @return verdictCount Number of active verdicts by this auditor.
    /// @return registered   Whether this address has registered a profile.
    /// @return profileURI   The registered profile URI ("" if none).
    /// @return registeredAt Registration timestamp (0 if never registered).
    function auditorStats(address auditor)
        external
        view
        returns (
            uint32 verdictCount,
            bool registered,
            string memory profileURI,
            uint64 registeredAt
        )
    {
        AuditorInfo storage info = _auditors[auditor];
        return (info.verdictCount, info.registered, info.profileURI, info.registeredAt);
    }

    /// @notice Whether `agent` has registered a profile.
    function isRegistered(address agent) external view returns (bool) {
        return _auditors[agent].registered;
    }

    // ------------------------------------------------------------------
    // Internal aggregate maintenance
    // ------------------------------------------------------------------

    function _addToAggregate(Aggregate storage agg, uint8 status, uint8 score) internal {
        if (status == STATUS_SAFE) agg.safeCount += 1;
        else if (status == STATUS_CAUTION) agg.cautionCount += 1;
        else agg.dangerCount += 1; // status is validated to 1..3 before this call
        agg.verdictCount += 1;
        agg.scoreSum += score;
    }

    function _removeFromAggregate(Aggregate storage agg, uint8 status, uint8 score) internal {
        if (status == STATUS_SAFE) agg.safeCount -= 1;
        else if (status == STATUS_CAUTION) agg.cautionCount -= 1;
        else agg.dangerCount -= 1;
        agg.verdictCount -= 1;
        agg.scoreSum -= score;
    }
}
