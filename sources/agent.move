// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Agent registration (public).
///
/// Anyone can register their agent. The caller's address becomes the agent id
/// and is the wallet that receives all job payments and competition prizes.
/// `owner` is stored as metadata only. The intake and competition modules read
/// this registry to gate who can be paid or who may compete.
module quadra::agent;

use std::string::String;
use sui::event;
use sui::table::{Self, Table};

/// The agent is already registered.
const EAlreadyRegistered: u64 = 0;
/// The agent is not registered.
const ENotRegistered: u64 = 1;

/// Stored metadata for one agent, keyed by the agent wallet address.
public struct AgentInfo has store {
    owner: address,
    name: String,
    description: String,
    category: String,
}

/// Shared registry of all agents.
public struct AgentRegistry has key {
    id: UID,
    agents: Table<address, AgentInfo>,
}

/// Emitted when an agent registers.
public struct AgentRegistered has copy, drop {
    agent_id: address,
    owner: address,
    name: String,
    category: String,
}

/// Create and share the registry once at publish.
fun init(ctx: &mut TxContext) {
    let registry = AgentRegistry {
        id: object::new(ctx),
        agents: table::new(ctx),
    };
    transfer::share_object(registry);
}

/// Register the caller as an agent. The caller's address is the agent id and
/// the payee for jobs and prizes; `owner` is stored as metadata only.
public fun register_agent(
    registry: &mut AgentRegistry,
    owner: address,
    name: String,
    description: String,
    category: String,
    ctx: &mut TxContext,
) {
    let agent_id = ctx.sender();
    assert!(!registry.agents.contains(agent_id), EAlreadyRegistered);
    registry.agents.add(agent_id, AgentInfo { owner, name, description, category });
    event::emit(AgentRegistered { agent_id, owner, name, category });
}

/// Update the caller's own agent metadata.
public fun update_agent(
    registry: &mut AgentRegistry,
    name: String,
    description: String,
    category: String,
    ctx: &TxContext,
) {
    let agent_id = ctx.sender();
    assert!(registry.agents.contains(agent_id), ENotRegistered);
    let info = registry.agents.borrow_mut(agent_id);
    info.name = name;
    info.description = description;
    info.category = category;
}

/// True if `agent_id` is registered. Used by intake and competition.
public fun is_registered(registry: &AgentRegistry, agent_id: address): bool {
    registry.agents.contains(agent_id)
}

/// Abort unless `agent_id` is registered (shared helper for other modules).
public fun assert_registered(registry: &AgentRegistry, agent_id: address) {
    assert!(registry.agents.contains(agent_id), ENotRegistered);
}

public fun owner(registry: &AgentRegistry, agent_id: address): address {
    registry.agents.borrow(agent_id).owner
}

public fun name(registry: &AgentRegistry, agent_id: address): String {
    registry.agents.borrow(agent_id).name
}

public fun description(registry: &AgentRegistry, agent_id: address): String {
    registry.agents.borrow(agent_id).description
}

public fun category(registry: &AgentRegistry, agent_id: address): String {
    registry.agents.borrow(agent_id).category
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
