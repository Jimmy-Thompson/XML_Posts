import Database from 'better-sqlite3';

const db = new Database('outputs/master_database/master_jobs.db');

console.log('🚗 VEHICLE FILTER BREAKDOWN - What Each Filter Actually Pulls\n');
console.log('='.repeat(80));

const vehicleFilters = [
  { name: 'Any', description: 'All jobs (no vehicle filter)', searchPattern: null },
  { name: 'Sedan', description: 'Jobs requiring a sedan', searchPattern: '%Sedan%' },
  { name: 'SUV', description: 'Jobs requiring an SUV', searchPattern: '%SUV%' },
  { name: 'Truck', description: 'Jobs requiring a truck', searchPattern: '%Truck%' },
  { name: 'Mini Van', description: 'Jobs requiring a mini van', searchPattern: '%Mini Van%' },
  { name: 'Cargo/Sprinter Van', description: 'SMART FILTER: Cargo Van OR Sprinter Van', searchPattern: null, isSmartFilter: true, patterns: ['%Cargo Van%', '%Sprinter Van%'] },
  { name: 'Box Truck', description: 'SMART FILTER: Box Truck OR Straight Truck', searchPattern: null, isSmartFilter: true, patterns: ['%Box Truck%', '%Straight Truck%'] },
  { name: 'Bike', description: 'Jobs requiring a bike/bicycle', searchPattern: '%Bike%' },
  { name: 'Foot', description: 'Jobs for walking/foot delivery', searchPattern: '%Foot%' }
];

vehicleFilters.forEach((filter, index) => {
  console.log(`\n${index + 1}. ${filter.name.toUpperCase()}`);
  console.log('-'.repeat(80));
  console.log(`Description: ${filter.description}`);
  
  let totalJobs = 0;
  let breakdown = [];
  
  if (filter.name === 'Any') {
    // Count all jobs
    const result = db.prepare(`SELECT COUNT(*) as count FROM jobs`).get();
    totalJobs = result.count;
    console.log(`Total Jobs: ${totalJobs}`);
    console.log('(Shows all jobs regardless of vehicle requirement)');
  } else if (filter.isSmartFilter) {
    // Smart filter with OR logic
    const whereClauses = filter.patterns.map(p => `vehicle_requirements LIKE '${p}' COLLATE NOCASE`).join(' OR ');
    const results = db.prepare(`
      SELECT vehicle_requirements, COUNT(*) as count 
      FROM jobs 
      WHERE ${whereClauses}
      GROUP BY vehicle_requirements 
      ORDER BY count DESC
    `).all();
    
    results.forEach(r => {
      totalJobs += r.count;
      breakdown.push(r);
    });
    
    console.log(`Total Jobs: ${totalJobs}`);
    console.log(`\nDatabase Search: ${filter.patterns.join(' OR ')}`);
    console.log('\nBreakdown by vehicle_requirements:');
    breakdown.slice(0, 10).forEach(b => {
      console.log(`  • ${b.vehicle_requirements}: ${b.count} jobs`);
    });
    if (breakdown.length > 10) {
      console.log(`  ... and ${breakdown.length - 10} more variants`);
    }
  } else {
    // Standard filter
    const results = db.prepare(`
      SELECT vehicle_requirements, COUNT(*) as count 
      FROM jobs 
      WHERE vehicle_requirements LIKE ? COLLATE NOCASE
      GROUP BY vehicle_requirements 
      ORDER BY count DESC
    `).all(filter.searchPattern);
    
    results.forEach(r => {
      totalJobs += r.count;
      breakdown.push(r);
    });
    
    console.log(`Total Jobs: ${totalJobs}`);
    console.log(`Database Search: vehicle_requirements LIKE '${filter.searchPattern}'`);
    
    if (breakdown.length > 0) {
      console.log('\nBreakdown by vehicle_requirements:');
      breakdown.forEach(b => {
        console.log(`  • ${b.vehicle_requirements}: ${b.count} jobs`);
      });
    } else {
      console.log('(No jobs currently in database with this requirement)');
    }
  }
});

console.log('\n' + '='.repeat(80));
console.log('\n✨ KEY INSIGHTS:\n');
console.log('📍 SMART FILTERS (use OR logic to match multiple vehicle types):');
console.log('   • Box Truck → Matches "Box Truck" OR "Straight Truck"');
console.log('   • Cargo/Sprinter Van → Matches "Cargo Van" OR "Sprinter Van"\n');
console.log('📍 These smart filters solve the UI/database mismatch where:');
console.log('   • Dropdown shows one option (e.g., "Box Truck")');
console.log('   • Database has separate entries (e.g., "Box Truck" + "Straight Truck")');
console.log('   • Filter intelligently includes BOTH types\n');

db.close();
